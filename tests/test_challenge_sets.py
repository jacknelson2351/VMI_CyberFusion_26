import json
import os
import tempfile
import unittest
from pathlib import Path

import config
import db


class ChallengeSetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sets_dir = Path(self.tmp) / "challenge_sets"
        self.index = self.sets_dir / "index.json"
        self.legacy = Path(self.tmp) / "challenges.json"
        # Seed a legacy file to migrate.
        self.legacy.write_text(json.dumps([
            {"id": "a1", "name": "chal one", "category": "misc", "status": "solved"},
            {"id": "a2", "name": "chal two", "category": "web", "status": "unsolved"},
        ]))
        # Redirect module-level paths in both config and db.
        self._save = {}
        for mod in (config, db):
            for attr in ("CHALLENGE_SETS_DIR", "SETS_INDEX_PATH", "DB_PATH"):
                if hasattr(mod, attr):
                    self._save[(mod.__name__, attr)] = getattr(mod, attr)
        config.CHALLENGE_SETS_DIR = self.sets_dir
        config.SETS_INDEX_PATH = self.index
        config.DB_PATH = self.legacy
        db.CHALLENGE_SETS_DIR = self.sets_dir
        db.SETS_INDEX_PATH = self.index
        db.DB_PATH = self.legacy

    def tearDown(self):
        for (modname, attr), val in self._save.items():
            setattr(config if modname == "config" else db, attr, val)

    def test_seed_migrates_legacy_and_is_idempotent(self):
        db.ensure_sets_seeded()
        self.assertTrue((self.sets_dir / "umdctf.json").exists())
        idx = json.loads(self.index.read_text())
        self.assertEqual(idx["active"], "umdctf")
        # Idempotent: second call does not add/duplicate sets.
        db.ensure_sets_seeded()
        idx2 = json.loads(self.index.read_text())
        self.assertEqual(list(idx2["sets"].keys()), ["umdctf"])

    def test_current_db_path_follows_active(self):
        db.ensure_sets_seeded()
        self.assertEqual(config.current_db_path(), self.sets_dir / "umdctf.json")

    def test_create_activate_list_delete(self):
        db.ensure_sets_seeded()
        sid = db.create_challenge_set("Picnic CTF", "PicnicCTF", [{"id": "z", "name": "z"}])
        self.assertTrue((self.sets_dir / f"{sid}.json").exists())
        self.assertTrue(db.activate_challenge_set(sid))
        self.assertEqual(config.current_db_path(), self.sets_dir / f"{sid}.json")
        listing = {s["id"]: s for s in db.list_challenge_sets()}
        self.assertTrue(listing[sid]["active"])
        self.assertEqual(listing["umdctf"]["count"], 2)
        self.assertEqual(listing["umdctf"]["solved"], 1)
        ok, active = db.delete_challenge_set(sid)
        self.assertTrue(ok)
        self.assertEqual(active, "umdctf")  # active falls back after deleting active set

    def test_cannot_delete_only_set(self):
        db.ensure_sets_seeded()
        ok, msg = db.delete_challenge_set("umdctf")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
