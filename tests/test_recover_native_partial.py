import unittest

from recover_native_partial import complete_prefix


class PartialPrefixTests(unittest.TestCase):
    def test_retains_complete_parts_and_trims_torn_payload_or_headers(self):
        first = b'--test\r\nContent-Length: 4\r\n\r\ndata'
        for tail in (b'', b'\r\n--test\r\nContent-Length: 6\r\n\r\nabc',
                     b'\r\n--test\r\nContent-Len', b'\r\n--test--\r\n'):
            self.assertEqual(complete_prefix(first + tail, 'multipart/x-mixed-replace;boundary=test'), first)
        second = b'\r\n--test\r\nContent-Length: 4\r\n\r\nmore'
        self.assertEqual(complete_prefix(first + second, 'multipart/x-mixed-replace;boundary=test'), first + second)

    def test_rejects_no_complete_frame_or_invalid_boundary(self):
        for data, kind in ((b'', 'multipart/x-mixed-replace;boundary=test'),
                           (b'--test\r\nContent-Length: 4\r\n\r\na', 'multipart/x-mixed-replace;boundary=test'),
                           (b'data', 'other')):
            with self.assertRaises(ValueError):
                complete_prefix(data, kind)
