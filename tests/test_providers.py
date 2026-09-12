import unittest

from config import DEFAULT_CONFIG, PROVIDER_PRESETS, migrate_config
import providers


class MigrationTests(unittest.TestCase):
    def _legacy(self):
        return {
            "openai_api_key": "sk-legacy-oai",
            "anthropic_api_key": "sk-legacy-ant",
            "solver_model": "gpt-5.1",
            "recon_model": "gpt-5-mini",
        }

    def test_seeds_registry_from_legacy(self):
        cfg = migrate_config(self._legacy())
        self.assertTrue(cfg["models"], "models should be seeded")
        self.assertEqual(cfg["keys"]["openai"], "sk-legacy-oai")
        self.assertEqual(cfg["keys"]["anthropic"], "sk-legacy-ant")
        self.assertEqual(cfg["roles"]["solver"], "gpt-5.1")
        self.assertEqual(cfg["roles"]["aux"], "gpt-5-mini")

    def test_seeds_abliterated_kimi_entry(self):
        cfg = migrate_config(self._legacy())
        ids = {m["id"] for m in cfg["models"]}
        self.assertIn("kimi-k3-abl", ids)
        kimi = next(m for m in cfg["models"] if m["id"] == "kimi-k3-abl")
        self.assertEqual(kimi["base_url"], PROVIDER_PRESETS["shannon"]["base_url"])
        self.assertEqual(kimi["provider_kind"], "openai_compat")

    def test_migration_is_idempotent(self):
        cfg = migrate_config(self._legacy())
        n = len(cfg["models"])
        again = migrate_config(cfg)
        self.assertEqual(len(again["models"]), n)

    def test_does_not_touch_prepopulated_models(self):
        cfg = {"models": [{"id": "x", "model_id": "x", "provider_kind": "openai_compat"}]}
        out = migrate_config(cfg)
        self.assertEqual(len(out["models"]), 1)


class ResolveTests(unittest.TestCase):
    def _cfg(self):
        return migrate_config({
            "openai_api_key": "sk-oai",
            "keys": {"shannon": "sk-shannon"},
            "solver_model": "gpt-5.1",
            "recon_model": "gpt-5-mini",
        })

    def test_resolve_by_role(self):
        cfg = self._cfg()
        solver = providers.resolve_role(cfg, "solver")
        self.assertEqual(solver.model_id, "gpt-5.1")
        aux = providers.resolve_role(cfg, "aux")
        self.assertEqual(aux.model_id, "gpt-5-mini")

    def test_resolve_by_id(self):
        cfg = self._cfg()
        spec = providers.resolve_model(cfg, "kimi-k3-abl")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.model_id, "kimi-k3-3bit-reap")
        self.assertEqual(spec.api_key, "sk-shannon")

    def test_key_reference_resolution(self):
        cfg = self._cfg()
        solver = providers.resolve_role(cfg, "solver")
        self.assertEqual(solver.api_key, "sk-oai")  # via keys.openai from migration

    def test_pricing_on_spec(self):
        cfg = self._cfg()
        spec = providers.resolve_model(cfg, "kimi-k3-abl")
        self.assertEqual(spec.pricing, (3.83, 19.12))

    def test_aux_falls_back_to_solver(self):
        cfg = {"models": [{"id": "only", "model_id": "only", "provider_kind": "openai_compat",
                           "api_key_ref": "openai"}],
               "keys": {"openai": "k"}, "roles": {"solver": "only"}}
        aux = providers.resolve_role(cfg, "aux")
        self.assertEqual(aux.id, "only")


class BuildClientTests(unittest.TestCase):
    def test_openai_compat_uses_base_url(self):
        spec = providers.ModelSpec(
            id="k", name="k", provider_kind="openai_compat", model_id="m",
            base_url="https://api.shannon-ai.com/v1", api_key="sk-x",
        )
        client, kind = providers.build_client(spec)
        self.assertEqual(kind, "openai_compat")
        self.assertIsNotNone(client)
        self.assertIn("shannon-ai.com", str(client.base_url))

    def test_no_key_yields_no_client(self):
        spec = providers.ModelSpec(id="k", name="k", provider_kind="openai_compat",
                                   model_id="m", api_key="")
        client, kind = providers.build_client(spec)
        self.assertIsNone(client)

    def test_none_spec(self):
        client, kind = providers.build_client(None)
        self.assertIsNone(client)


if __name__ == "__main__":
    unittest.main()
