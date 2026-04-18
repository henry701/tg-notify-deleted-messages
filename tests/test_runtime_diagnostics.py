import unittest
from unittest.mock import patch

from packages.runtime_diagnostics import (
    format_process_runtime_snapshot,
    read_process_runtime_snapshot,
)


class RuntimeDiagnosticsTests(unittest.TestCase):
    @patch("packages.runtime_diagnostics.asyncio.all_tasks", return_value={1, 2, 3})
    @patch("packages.runtime_diagnostics.os.listdir", return_value=["1", "2"])
    def test_reads_process_runtime_snapshot_from_status_text(
        self, _mock_listdir, _mock_all_tasks
    ):
        snapshot = read_process_runtime_snapshot(
            "\n".join(
                [
                    "Name:\tpython3",
                    "VmRSS:\t   1234 kB",
                    "VmSwap:\t   5678 kB",
                    "VmSize:\t   9012 kB",
                    "Threads:\t17",
                ]
            )
        )

        self.assertEqual(
            snapshot,
            {
                "rss_kb": 1234,
                "swap_kb": 5678,
                "vm_size_kb": 9012,
                "threads": 17,
                "open_fds": 2,
                "asyncio_tasks": 3,
            },
        )

    def test_formats_process_runtime_snapshot(self):
        formatted = format_process_runtime_snapshot(
            {
                "rss_kb": 1234,
                "swap_kb": 5678,
                "vm_size_kb": 9012,
                "threads": 17,
                "open_fds": 2,
                "asyncio_tasks": 3,
            }
        )

        self.assertEqual(
            formatted,
            "rss_kb=1234 swap_kb=5678 vm_size_kb=9012 threads=17 open_fds=2 asyncio_tasks=3",
        )
