"""The hashfile lists every scanned path, so a new one is private, sidecars
included, and the mode of an existing one is left to its owner.

oans used to chmod the hashfile 0600 after SQLite had opened it in WAL mode,
by which point the -wal and -shm files existed with the umask's mode (0644
under 022) - world-readable for the whole first scan, and for good if that
run crashed. It also re-ran the chmod on every read-write open, reverting an
admin's 0640 each run and failing the open of a file it did not own.
"""

import os
import signal
import stat
import subprocess

from harness import (DUPEREMOVE, DuperemoveTest, _settle_scratch,
                     skip_without_hooks,
                     requires_real_binary, requires_reflink)

MiB = 1 << 20


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class HashfileModeTest(DuperemoveTest):
    @requires_reflink
    @requires_real_binary   # the hook stops oans, not a wrapper around it
    def test_a_new_hashfile_and_its_sidecars_are_private_during_the_scan(self):
        self.mkrand("tree/image", 4 * MiB)
        _settle_scratch()   # extents must exist to be hashed

        env = dict(os.environ,
                   DUPEREMOVE_CHECKPOINT_BYTES=str(MiB),
                   DUPEREMOVE_CHECKPOINT_PAUSE="1")
        skip_without_hooks(env)
        self.assertFalse(os.path.exists(self.hf))
        p = subprocess.Popen(
            [DUPEREMOVE, "-q", "--io-threads=1", "--hashfile", self.hf,
             "-r", self.path("tree")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
            preexec_fn=lambda: os.umask(0o022))
        try:
            _, status = os.waitpid(p.pid, os.WUNTRACED)
            self.assertTrue(os.WIFSTOPPED(status),
                            "the run ended before its first hash checkpoint")
            modes = {}
            for suffix in ("", "-wal", "-shm"):
                path = self.hf + suffix
                self.assertTrue(os.path.exists(path), f"no {path} mid-scan")
                modes[suffix or "hashfile"] = _mode(path)
        finally:
            if p.poll() is None:
                os.kill(p.pid, signal.SIGCONT)
        self.assertEqual(0, p.wait(timeout=60), "the resumed run failed")

        for name, mode in modes.items():
            self.assertEqual(0o600, mode, f"{name} is {oct(mode)} mid-scan")
        self.assertEqual(0o600, _mode(self.hf))

    def test_an_existing_hashfile_keeps_the_mode_its_owner_gave_it(self):
        self.write("tree/a", b"a" * 8192)
        self.dm("-r", self.path("tree"))
        self.assertDmOk()
        self.assertEqual(0o600, _mode(self.hf))

        os.chmod(self.hf, 0o640)
        self.dm("-r", self.path("tree"))
        self.assertDmOk()
        self.assertEqual(0o640, _mode(self.hf))
