import json
import unittest

from cloud_client import CloudClient, encode, receive


class Stream:
    def __init__(self, replies):
        self.data = bytearray(b"".join(encode(r) for r in replies))
        self.sent = []
        self.closed = False

    def recv(self, size):
        count = min(size, 3, len(self.data))
        data = bytes(self.data[:count])
        del self.data[:count]
        return data

    def sendall(self, data):
        self.sent.append(json.loads(data[4:]))

    def close(self):
        self.closed = True


INFO = {"dev_id": "A" * 40, "mac": "02-00-00-00-00-01", "device_model": "H500",
        "hw_version": "1.0", "sw_version": "1.0.0"}


class CloudTests(unittest.TestCase):
    def test_disabled_client_cannot_open_connection(self):
        def forbidden():
            self.fail("disabled client opened a connection")
        cloud = CloudClient(INFO, "unused", connector=forbidden)
        self.assertFalse(cloud.hello())
        self.assertFalse(cloud.bind("owner@example.invalid", "secret"))
        self.assertEqual(cloud.last_stage, "disabled")
        with self.assertRaises(PermissionError):
            cloud.connect()

    def test_fragmented_frames_and_eof(self):
        stream = Stream([{"id": 1, "error_code": 0}])
        self.assertEqual(receive(stream)["id"], 1)
        with self.assertRaises(ConnectionError):
            receive(stream)
        with self.assertRaises(ValueError):
            encode({"large": "x" * 65536})

    def test_rejected_identity_never_sends_credentials(self):
        stream = Stream([{"id": 1, "error_code": -1}])
        cloud = CloudClient(INFO, "unused", connector=lambda: stream, enabled=True)
        self.assertFalse(cloud.bind("owner@example.invalid", "secret"))
        self.assertEqual([r["method"] for r in stream.sent], ["helloCloud"])
        self.assertNotIn("secret", json.dumps(stream.sent))
        self.assertTrue(stream.closed)
        self.assertFalse(cloud.bind("owner@example.invalid", "secret"))
        self.assertEqual(len(stream.sent), 1)  # Failed app retries are rate limited.

    def test_cloud_confirmation_required(self):
        for result, expected in (({}, False), ({"accountId": "123"}, True)):
            stream = Stream([{"id": 1, "error_code": 0, "result": {"illegalType": 0}},
                             {"id": 2, "error_code": 0, "result": result}])
            cloud = CloudClient(INFO, "unused", connector=lambda: stream, enabled=True)
            self.assertEqual(cloud.bind("owner@example.invalid", "test"), expected)
            cloud.stop.set()
            cloud.close()


if __name__ == "__main__":
    unittest.main()
