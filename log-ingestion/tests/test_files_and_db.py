"""Reader + SQLite + full-loop tests (temporary folders only, no lab needed)."""

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from logingest import store  # noqa: E402
from logingest.config import Config, Source, load_config  # noqa: E402
from logingest.main import Ingestor  # noqa: E402
from logingest.reader import read_new_lines  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def L(i, uid=None):
    """A valid conn line with a unique uid/ts."""
    uid = uid or f"Cuid{i:06d}"
    return (f'{{"ts":{1795115970 + i}.5,"uid":"{uid}","id.orig_h":"10.10.10.{i % 250 + 1}","id.orig_p":{40000 + i % 20000},'
            f'"id.resp_h":"10.10.20.20","id.resp_p":80,"proto":"tcp","conn_state":"SF","history":"ShADadFf"}}\n').encode()


def S(i=1):
    return (f'{{"ts":{1795115970 + i}.5,"host":"10.10.35.10","host_p":22,'
            f'"software_type":"SERVER","name":"OpenSSH",'
            f'"version":{{"major":9,"minor":9}},"unparsed_version":"OpenSSH_9.9p1"}}\n').encode()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="logingest-test-"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, probes=("probe1",), types=("conn",), chunk=1_048_576):
        sources = []
        for p in probes:
            (self.dir / p).mkdir(exist_ok=True)
            for t in types:
                sources.append(Source(p, t, self.dir / p / f"{t}.log"))
        cfg = Config(self.dir / "db" / "test.db", tuple(sources), 0.05, chunk)
        return cfg, Ingestor(cfg)

    def count(self, ing, table="observations"):
        return ing.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class Reader(Tmp):
    def test_partial_line_waits(self):
        f = self.dir / "conn.log"
        f.write_bytes(L(1) + L(2)[:30])
        r = read_new_lines(f, None, 4096)
        self.assertEqual(len(r.lines), 1)
        with open(f, "ab") as h:
            h.write(L(2)[30:])
        r2 = read_new_lines(f, r.state, 4096)
        self.assertEqual([x.raw + b"\n" for x in r2.lines], [L(2)])
        self.assertFalse(r2.new_generation)

    def test_truncate_and_regrow_past_offset(self):
        f = self.dir / "conn.log"
        f.write_bytes(L(1) + L(2))
        r = read_new_lines(f, None, 4096)
        with open(f, "r+b") as h:  # same inode, truncated, then longer than before
            h.truncate(0)
            h.write(L(10) + L(11) + L(12))
        r2 = read_new_lines(f, r.state, 4096)
        self.assertTrue(r2.new_generation)
        self.assertEqual(len(r2.lines), 3)

    def test_delete_and_recreate(self):
        f = self.dir / "conn.log"
        f.write_bytes(L(1))
        r = read_new_lines(f, None, 4096)
        f.unlink()
        self.assertIsNone(read_new_lines(f, r.state, 4096))
        f.write_bytes(L(1) + L(2))  # same first line, new inode
        r2 = read_new_lines(f, r.state, 4096)
        self.assertTrue(r2.new_generation)
        self.assertEqual(len(r2.lines), 2)

    def test_oversize_line(self):
        f = self.dir / "conn.log"
        f.write_bytes(b"x" * 5000 + b"\n" + L(1))
        r = read_new_lines(f, None, 4096)
        self.assertTrue(r.lines[0].oversize)
        self.assertTrue(r.more)


class Store(Tmp):
    def test_idempotent_reingest(self):
        cfg, ing = self.make()
        cfg.sources[0].path.write_bytes(b"".join(L(i) for i in range(50)))
        ing.run_once()
        ing.con.execute("PRAGMA foreign_keys=OFF")
        ing.con.execute("DELETE FROM file_offsets")  # forget positions -> everything read again
        c = ing.run_once()
        self.assertEqual((c.inserted, c.duplicates), (0, 50))
        self.assertEqual(self.count(ing), 50)

    def test_sequence_never_reused_after_delete(self):
        cfg, ing = self.make()
        cfg.sources[0].path.write_bytes(L(1) + L(2))
        ing.run_once()
        ing.con.execute("DELETE FROM observations")
        with open(cfg.sources[0].path, "ab") as h:
            h.write(L(3))
        ing.run_once()
        self.assertEqual(ing.con.execute("SELECT sequence FROM observations").fetchone()[0], 3)

    def test_cursor_reads_each_row_once_in_sequence_order(self):
        cfg, ing = self.make()
        # out-of-order ts in the file, as Zeek really writes it
        cfg.sources[0].path.write_bytes(L(5) + L(1) + L(3))
        ing.run_once()
        cur, seen = store.get_cursor(ing.con, "module5"), []
        while batch := store.read_batch(ing.con, cur, limit=2):
            seen += [o["data"]["zeek_uid"] for o in batch]
            cur = batch[-1]["sequence"]
            store.save_cursor(ing.con, "module5", cur, "now")
        self.assertEqual(seen, ["Cuid000005", "Cuid000001", "Cuid000003"])
        self.assertEqual(store.get_cursor(ing.con, "module5"), 3)

    def test_rows_and_offset_commit_together(self):
        cfg, ing = self.make()
        cfg.sources[0].path.write_bytes(L(1) + L(2))
        orig = store.store_batch

        def crash_midway(con, sid, probe, lt, state, obs, rej, now):
            # the offset and the first row are written, then the batch dies inside the transaction
            return orig(con, sid, probe, lt, state, obs[:1] + [{}], rej, now)
        store.store_batch = crash_midway
        try:
            with self.assertRaises(KeyError):
                ing.run_once()
        finally:
            store.store_batch = orig
        self.assertEqual(self.count(ing), 0)
        self.assertIsNone(store.load_offset(ing.con, "probe1:conn"))
        ing.run_once()
        self.assertEqual(self.count(ing), 2)

    def test_bad_lines_go_to_rejected_records(self):
        cfg, ing = self.make()
        cfg.sources[0].path.write_bytes(L(1) + b"not json\n" + b'{"ts":1}\n' + L(2))
        c = ing.run_once()
        self.assertEqual((c.inserted, c.rejected), (2, 2))
        codes = sorted(r[0] for r in ing.con.execute("SELECT error_code FROM rejected_records"))
        self.assertEqual(codes, ["invalid_json", "missing_field"])


class FullLoop(Tmp):
    def test_two_probes_same_flow_are_two_observations(self):
        cfg, ing = self.make(probes=("probe1", "probe2"), types=("conn", "dhcp"))
        for p in ("probe1", "probe2"):
            for t in ("conn", "dhcp"):
                shutil.copy(FIX / p / f"{t}.log", self.dir / p / f"{t}.log")
        c = ing.run_once()
        expected = sum(len(f.read_bytes().splitlines()) for f in FIX.glob("*/*.log"))
        self.assertEqual((c.inserted, c.rejected), (expected, 0))
        # pc -> web1 :80 at the same moment, seen by both probes
        rows = ing.con.execute("SELECT probe_id FROM observations WHERE src_ip='10.10.10.127' "
                               "AND dst_ip='10.10.20.20' AND json_extract(data_json,'$.src_port')=38180").fetchall()
        self.assertEqual(sorted(r[0] for r in rows), ["probe1", "probe2"])

    def test_two_probes_same_software_are_two_observations(self):
        cfg, ing = self.make(probes=("probe1", "probe2"), types=("software",))
        for p in ("probe1", "probe2"):
            (self.dir / p / "software.log").write_bytes(S())
        c = ing.run_once()
        self.assertEqual((c.inserted, c.rejected), (2, 0))
        rows = ing.con.execute("SELECT probe_id, event_type, data_json FROM observations "
                               "WHERE log_type='software' ORDER BY probe_id").fetchall()
        self.assertEqual([r[0] for r in rows], ["probe1", "probe2"])
        self.assertEqual([r[1] for r in rows], ["software_observation", "software_observation"])
        self.assertEqual([json.loads(r[2])["software_name"] for r in rows], ["OpenSSH", "OpenSSH"])

    def test_software_is_delivered_through_read_cursor(self):
        cfg, ing = self.make(types=("software",))
        cfg.sources[0].path.write_bytes(S())
        self.assertEqual((ing.run_once().inserted, self.count(ing)), (1, 1))
        batch = store.read_batch(ing.con, 0, limit=1)
        self.assertEqual(batch[0]["event_type"], "software_observation")
        self.assertEqual(batch[0]["data"]["host_ip"], "10.10.35.10")
        store.save_cursor(ing.con, "module5", batch[-1]["sequence"], "now")
        self.assertEqual(store.get_cursor(ing.con, "module5"), batch[-1]["sequence"])
        self.assertEqual(store.read_batch(ing.con, batch[-1]["sequence"], limit=1), [])

    def test_zeek_restart_with_archive_loses_nothing(self):
        cfg, ing = self.make()
        live = cfg.sources[0].path
        live.write_bytes(L(1) + L(2))
        ing.run_once()
        with open(live, "ab") as h:  # written but NOT read yet
            h.write(L(3) + L(4))
        # what start-zeek.sh does: move old logs to archive/<time>/, Zeek makes a new file
        arch = live.parent / "archive" / "1795200000"
        arch.mkdir(parents=True)
        os.rename(live, arch / live.name)
        live.write_bytes(L(5))
        c = ing.run_once()
        self.assertEqual((c.inserted, c.duplicates), (3, 2))  # L3,L4 from archive + L5; L1,L2 dupes
        self.assertEqual(self.count(ing), 5)
        self.assertEqual(ing.run_once().lines, 0)

    def test_kill_9_and_restart(self):
        """SIGKILL the real process mid-run, restart, nothing lost or doubled."""
        (self.dir / "p").mkdir()
        log = self.dir / "p" / "conn.log"
        n = 30_000
        log.write_bytes(b"".join(L(i) for i in range(n)))
        conf = self.dir / "c.toml"
        conf.write_text(f'database = "db/k.db"\nread_chunk_bytes = 65536\n'
                        f'[[sources]]\nprobe_id = "probe1"\nlog_type = "conn"\npath = "{log}"\n')
        cmd = [sys.executable, "-m", "logingest", "-c", str(conf), "run"]
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        db = self.dir / "db" / "k.db"
        deadline = time.time() + 20
        while time.time() < deadline:  # kill once some, but not all, rows are in
            try:
                with sqlite3.connect(db, timeout=5) as c:
                    k = c.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
                if k > 1000:
                    break
            except sqlite3.Error:
                pass
            time.sleep(0.01)
        p.send_signal(signal.SIGKILL)
        p.wait()
        subprocess.run(cmd[:-1] + ["run", "--once"], cwd=ROOT, check=True, capture_output=True)
        con = sqlite3.connect(db)
        total, distinct = con.execute("SELECT COUNT(*), COUNT(DISTINCT event_id) FROM observations").fetchone()
        self.assertEqual((total, distinct), (n, n))
        self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        seqs = [r[0] for r in con.execute("SELECT sequence FROM observations ORDER BY sequence")]
        self.assertEqual(seqs, sorted(set(seqs)))


class ConfigFile(Tmp):
    def test_shipped_config_loads(self):
        cfg = load_config(ROOT / "config.toml")
        self.assertEqual([s.source_id for s in cfg.sources],
                         ["probe1:conn", "probe1:dhcp", "probe1:software",
                          "probe2:conn", "probe2:dhcp", "probe2:software"])


if __name__ == "__main__":
    unittest.main()
