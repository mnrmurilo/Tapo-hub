"""Extract TC70 v5's private G711u PES track without changing video timestamps."""


class AudioPES:
    def __init__(self):
        self.pmt = self.pid = self.counter = None
        self.pending = bytearray()
        self.needed = None

    @staticmethod
    def section(payload):
        offset = 1 + payload[0]
        data = payload[offset:]
        if len(data) < 3:
            raise ValueError("Truncated transport table")
        length = 3 + ((data[1] & 15) << 8 | data[2])
        # TC70's tables fit in one TS packet; reject unsupported layouts.
        if length > len(data):
            raise ValueError("Unsupported transport table layout")
        return data[:length]

    def feed(self, data):
        if len(data) % 188:
            raise ValueError("Truncated transport packet")
        result = []
        for offset in range(0, len(data), 188):
            packet = data[offset:offset + 188]
            if packet[0] != 0x47 or packet[1] & 0x80 or packet[3] & 0xc0:
                raise ValueError("Invalid transport packet")
            pid = (packet[1] & 31) << 8 | packet[2]
            control = packet[3] >> 4 & 3
            if control not in (1, 3):
                continue
            start = 4 + (1 + packet[4] if control == 3 else 0)
            if start >= 188:
                continue
            payload = packet[start:]
            first = bool(packet[1] & 64)
            if first and pid == 0:
                table = self.section(payload)
                if table[0] != 0 or len(table) < 16:
                    raise ValueError("Invalid PAT")
                self.pmt = (table[10] & 31) << 8 | table[11]
            elif first and pid == self.pmt:
                table = self.section(payload)
                if table[0] != 2 or len(table) < 16:
                    raise ValueError("Invalid PMT")
                position = 12 + ((table[10] & 15) << 8 | table[11])
                while position + 5 <= len(table) - 4:
                    kind = table[position]
                    track = (table[position + 1] & 31) << 8 | table[position + 2]
                    if kind == 0x91:
                        if self.pid is not None and self.pid != track:
                            raise ValueError("Audio track changed")
                        self.pid = track
                    position += 5 + ((table[position + 3] & 15) << 8 | table[position + 4])
            elif pid == self.pid:
                counter = packet[3] & 15
                if self.counter is not None and counter != (self.counter + 1) % 16:
                    raise ValueError("Audio packet loss")
                self.counter = counter
                if first:
                    if self.pending:
                        raise ValueError("Incomplete audio PES")
                    if len(payload) < 9 or payload[:4] != b"\x00\x00\x01\xc0":
                        raise ValueError("Invalid audio PES")
                    length = int.from_bytes(payload[4:6], "big")
                    header = 9 + payload[8]
                    self.needed = length - (header - 6)
                    if not 0 < self.needed <= 65535 or header > len(payload):
                        raise ValueError("Invalid audio PES length")
                    payload = payload[header:]
                if self.needed is not None:
                    self.pending.extend(payload[:self.needed - len(self.pending)])
                    if len(self.pending) == self.needed:
                        result.append(bytes(self.pending))
                        self.pending.clear()
                        self.needed = None
        return result
