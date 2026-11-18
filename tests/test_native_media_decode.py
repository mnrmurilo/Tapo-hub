import hashlib
import unittest

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from native_media_decode import decode_snapshot, decode_stream, nal_units


class NativeDecodeTests(unittest.TestCase):
    def test_c400_quantized_audio_timestamps_resolve_to_16khz_and_reject_unknown_rates(self):
        from unittest.mock import patch
        picture = b'\x00\x00\x01\x65picture'
        for sample_size, interval, expected in ((1120, None, 16000), (560, None, 8000), (1323, 0.06, None)):
            body = bytearray()
            for i in range(32):
                timestamp = round((i * .07 + (.01 if i % 2 else 0)) if interval is None else i * interval, 3)
                kind, payload = ('video/x-h264', picture) if i == 0 else ('audio/g711u', b'a' * sample_size)
                body.extend((f'--test\r\nContent-Type: {kind}\r\nContent-Length: {len(payload)}\r\n'
                             f'X-Decrypt-Length: {len(payload)}\r\nX-Timestamp: {timestamp}\r\n'
                             'X-Frame-Width: 2304\r\nX-Frame-Height: 1296\r\nX-FrameRate: 15\r\n\r\n').encode())
                body.extend(payload + b'\r\n')
            with patch('native_media_decode.decrypt_payload', side_effect=lambda payload, *args: payload):
                if expected is None:
                    with self.assertRaisesRegex(ValueError, 'audio sample rate'):
                        decode_stream(bytes(body), self.nonce, self.password, 'multipart/x-mixed-replace;boundary=test')
                else:
                    result = decode_stream(bytes(body), self.nonce, self.password, 'multipart/x-mixed-replace;boundary=test')
                    self.assertEqual(result['audio_rate'], expected)

    nonce, password = "a"*32, "B"*64

    def test_h264_parameter_units_support_both_annexb_start_codes(self):
        sps = b"\x00\x00\x00\x01\x67profile"
        pps = b"\x00\x00\x01\x68picture"
        frame = b"\x00\x00\x00\x01\x65frame"
        self.assertEqual(nal_units(sps + pps + frame), [(7, sps), (8, pps), (5, frame)])

    def encrypt(self, plain):
        key = hashlib.md5((self.nonce + ":" + self.password).encode()).digest()
        iv = hashlib.md5(("admin:" + self.nonce).encode()).digest()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(padded) + enc.finalize()

    def test_snapshot_accepts_observed_trailer_but_rejects_wrong_lengths(self):
        plain = b"\xff\xd8test\xff\xd9" + b"T"*16
        self.assertEqual(decode_snapshot(self.encrypt(plain), self.nonce, self.password, len(plain)), plain[:-16])
        with self.assertRaises(ValueError):
            decode_snapshot(self.encrypt(plain), self.nonce, self.password, len(plain)-1)

    def test_configuration_only_parts_are_attached_to_next_picture_and_tail_is_ignored(self):
        config = b'\x00\x00\x01\x67sps\x00\x00\x01\x68pps'
        picture = b'\x00\x00\x01\x65picture'
        sei = b'\x00\x00\x01\x06metadata'
        body = bytearray()
        for timestamp, plain in enumerate((config, picture + sei, picture + sei, config)):
            encrypted = self.encrypt(plain)
            body.extend((f'--test\r\nContent-Type: video/x-h264\r\nContent-Length: {len(encrypted)}\r\n'
                         f'X-Decrypt-Length: {len(plain)}\r\nX-Timestamp: {timestamp}\r\n'
                         'X-Frame-Width: 2304\r\nX-Frame-Height: 1296\r\nX-FrameRate: 15\r\n\r\n').encode())
            body.extend(encrypted + b'\r\n')
        result = decode_stream(bytes(body), self.nonce, self.password, 'multipart/x-mixed-replace;boundary=test')
        self.assertEqual(result['video'], config + picture + sei + picture)
        self.assertEqual(result['video_pts'], [1.0, 2.0])

    def test_video_and_audio_are_both_decrypted_and_frames_are_bounded(self):
        video = b"\x00\x00\x00\x01\x65test"
        audio = b"\xff"*960
        body = bytearray()
        for kind, plain, timestamp in (("video/x-h264", video, "0.0"),
                                      ("audio/g711u", audio, "0.0"), ("audio/g711u", audio, "0.06")):
            encrypted = self.encrypt(plain)
            header = ("--data-boundary--\r\nContent-Type: " + kind + "\r\nContent-Length: " + str(len(encrypted))
                      + "\r\nX-Timestamp: " + timestamp + "\r\nX-Decrypt-Length: " + str(len(plain))
                      + "\r\nX-Frame-Width: 2304\r\nX-Frame-Height: 1296\r\nX-FrameRate: 15\r\n\r\n")
            body.extend(header.encode() + encrypted + b"\r\n")
        media = decode_stream(bytes(body), self.nonce, self.password,
                              "multipart/x-mixed-replace;boundary=data-boundary--")
        self.assertEqual(media["video"], video)
        self.assertEqual(media["audio"], audio*2)
        self.assertEqual(media["audio_rate"], 16000)
        with self.assertRaises(ValueError):
            decode_stream(bytes(body[:-10]), self.nonce, self.password,
                          "multipart/x-mixed-replace;boundary=data-boundary--")


if __name__ == "__main__":
    unittest.main()
