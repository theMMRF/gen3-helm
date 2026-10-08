"""Render both frontend layouts and assert graph gates and default compatibility."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/revproxy"
GUARD = 'auth_request /gen3-authz;'


def render(frontend, enabled=None, overrides=None, check=True):
    values = {"global": {"hostname": "commons.example", "frontendRoot": frontend}}
    if enabled is not None:
        values["graphMetadataAdmin"] = {"enabled": enabled}
    if overrides:
        values["additionalConfigs"] = overrides
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        return subprocess.run(["helm", "template", "test", str(CHART), "-f", f.name],
                              text=True, capture_output=True, check=check)


def configs(result):
    docs = list(yaml.safe_load_all(result.stdout))
    return next(d["data"] for d in docs if d and d.get("kind") == "ConfigMap"
                and d["metadata"]["name"] == "revproxy-nginx-subconf")


class GraphMetadataGateTests(unittest.TestCase):
    def test_both_layouts_default_public_and_explicit_disabled_identical(self):
        for frontend in ("gen3ff", "portal"):
            with self.subTest(frontend=frontend):
                implicit, disabled = configs(render(frontend)), configs(render(frontend, False))
                self.assertEqual(implicit, disabled)
                for filename in ("peregrine-service.conf", "sheepdog-service.conf", "portal-service.conf"):
                    self.assertNotIn(GUARD, implicit[filename])

    def test_every_sensitive_route_protected_while_other_configs_unchanged(self):
        for frontend in ("gen3ff", "portal"):
            with self.subTest(frontend=frontend):
                original, gated = configs(render(frontend)), configs(render(frontend, True))
                routes = {
                    "peregrine-service.conf": ["/api/search", "/api/v0/submission/graphql", "/api/v0/submission/getschema"],
                    "sheepdog-service.conf": ["/api/"],
                    "portal-service.conf": ["/portal" if frontend == "gen3ff" else "/"],
                }
                for filename, paths in routes.items():
                    self.assertEqual(gated[filename].count(GUARD), len(paths))
                    for path in paths:
                        block = gated[filename].split("location " + path + " {", 1)[1].split("}", 1)[0]
                        self.assertIn(GUARD, block)
                        self.assertIn('set $authz_resource "/services/graph-metadata";', block)
                        self.assertIn('set $authz_service "peregrine";', block)
                        self.assertIn('set $authz_method "access";', block)
                for filename in original:
                    if filename not in routes:
                        self.assertEqual(original[filename], gated[filename], filename)
                self.assertEqual(original['peregrine-service.conf'].split('location /api/search')[0],
                                 gated['peregrine-service.conf'].split('location /api/search')[0])

    def test_protected_overrides_fail_closed_only_when_enabled(self):
        for filename in ("peregrine-service.conf", "sheepdog-service.conf", "portal-service.conf"):
            result = render("gen3ff", True, {filename: "location /bypass { return 200; }"}, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("graphMetadataAdmin cannot protect", result.stderr)
        self.assertEqual(render("gen3ff", False, {"peregrine-service.conf": "# custom"}).returncode, 0)
        self.assertEqual(render("gen3ff", True, {"argo-host.conf": "# custom"}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
