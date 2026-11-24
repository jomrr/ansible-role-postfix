"""Check the lifecycle of real filesystem locks across abrupt process termination."""

import fcntl
import multiprocessing
import os
import signal
import unittest
from multiprocessing.connection import Connection
from pathlib import Path
from tempfile import TemporaryDirectory

from library.postfix_activate import candidate_workspace


def hold_candidate(root: Path, notify: Connection) -> None:
    """Leave a candidate in use until the parent simulates a hard abort."""
    with candidate_workspace(root) as (stage, _):
        (stage / "main.cf").write_text("inet_interfaces = all\n", encoding="utf-8")
        notify.send(stage)
        signal.pause()


class WorkspaceTests(unittest.TestCase):
    """Use separate processes so the operating system owns the lock lifetime."""

    def test_orphan_recovery_preserves_live_and_unrelated_paths(self) -> None:
        """A crash releases the lock, and only the abandoned private directory is reclaimed."""
        with TemporaryDirectory() as temp:
            root = Path(temp)
            other = root / ".candidate-operator-backup"
            other.mkdir(mode=0o700)
            link = root / ".candidate-deadbeef"
            link.symlink_to(other, target_is_directory=True)
            context = multiprocessing.get_context("spawn")
            reader, writer = context.Pipe(duplex=False)
            worker = context.Process(target=hold_candidate, args=(root, writer))
            worker.start()
            try:
                self.assertTrue(reader.poll(10), "worker did not acquire its workspace")
                abandoned = reader.recv()
                descriptor = os.open(root, os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.assertTrue((abandoned / "main.cf").is_file())
                finally:
                    os.close(descriptor)
            finally:
                worker.kill()
                worker.join(10)
                reader.close()
                writer.close()
            self.assertEqual(worker.exitcode, -signal.SIGKILL)
            self.assertTrue(abandoned.is_dir())
            with candidate_workspace(root, check_mode=True) as (_, count):
                self.assertEqual(count, 1)
                self.assertTrue(abandoned.is_dir())
            with candidate_workspace(root) as (fresh, count):
                self.assertEqual(count, 1)
                self.assertFalse(abandoned.exists())
                self.assertTrue(fresh.is_dir())
            self.assertFalse(fresh.exists())
            self.assertTrue(link.is_symlink())
            self.assertTrue(other.is_dir())
