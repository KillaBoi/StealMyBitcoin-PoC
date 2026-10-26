"""Regression test for the RecordingReader flush failure.

http.client calls flush() on the object returned by makefile() when it writes a
request through a shared pipelined connection. RecordingReader did not define
flush(), so that path raised AttributeError instead of sending the request.

Run with: python -m unittest discover -s tests
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stealmybitcoin_poc import RecordingReader, SharedSocket  # noqa: E402


class RecordingReaderFlushTest(unittest.TestCase):
    def test_flush_is_callable_and_keeps_recorded_bytes(self):
        reader = RecordingReader(io.BytesIO(b"HTTP/1.1 200 OK\r\n\r\nbody"))
        reader.flush()
        self.assertEqual(reader.read(12), b"HTTP/1.1 200")
        self.assertEqual(reader.chunks, [b"HTTP/1.1 200"])

    def test_shared_socket_exposes_a_flushable_file(self):
        reader = RecordingReader(io.BytesIO(b""))
        shared = SharedSocket(reader)
        shared.makefile("rb").flush()


if __name__ == "__main__":
    unittest.main()
