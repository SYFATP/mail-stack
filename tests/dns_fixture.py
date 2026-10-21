"""Isolated DNS authority for *.test, implemented using only Python stdlib."""
import socketserver
import struct


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            labels, offset = [], 12
            while data[offset]:
                length = data[offset]
                labels.append(data[offset + 1:offset + 1 + length].decode("ascii"))
                offset += length + 1
            offset += 1
            kind, dns_class = struct.unpack("!HH", data[offset:offset + 4])
            end = offset + 4
            name = ".".join(labels).lower()
            answer = b""
            if name.endswith(".test"):
                if kind == 1:
                    answer = bytes([172, 31, 240, 11])
                elif kind == 15:
                    answer = struct.pack("!H", 10) + encode_name("mail.example.test")
                elif kind == 16:
                    value = b"v=spf1 -all"
                    answer = bytes([len(value)]) + value
                flags = 0x8580
            else:
                flags = 0x8583
            count = int(bool(answer))
            packet = data[:2] + struct.pack("!HHHHH", flags, 1, count, 0, 0) + data[12:end]
            if answer:
                packet += b"\xc0\x0c" + struct.pack("!HHIH", kind, dns_class, 30, len(answer)) + answer
            sock.sendto(packet, self.client_address)
        except (IndexError, ValueError, UnicodeError, struct.error):
            pass


if __name__ == "__main__":
    with socketserver.UDPServer(("0.0.0.0", 53), Handler) as server:
        server.serve_forever()
