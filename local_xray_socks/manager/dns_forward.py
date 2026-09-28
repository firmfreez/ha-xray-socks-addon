"""Small uncached DNS forwarder, run as the same restricted UID as SOCKS.

UDP queries use TCP upstream to avoid truncation/retry ambiguity. Downstream
UDP answers are capped at 512 bytes and marked truncated for TCP retry.
"""
import socket
import socketserver
import struct
import sys
import threading


def read_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise OSError('Unexpected DNS EOF')
        chunks.extend(chunk)
    return bytes(chunks)


def minimal_reply(query, rcode=0, truncated=False):
    if len(query) < 12 or query[4:6] != b'\x00\x01':
        raise ValueError('Expected one DNS question')
    pos = 12
    while True:
        if pos >= len(query):
            raise ValueError('Incomplete DNS question')
        size = query[pos]
        pos += 1
        if size == 0:
            break
        if size > 63:
            raise ValueError('Compressed query names are unsupported')
        pos += size
    pos += 4
    if pos > len(query):
        raise ValueError('Incomplete DNS question')
    flags = bytes([0x80 | (query[2] & 1) | (2 if truncated else 0), 0x80 | rcode])
    return query[:2] + flags + b'\x00\x01' + b'\0' * 6 + query[12:pos]


def forward(query, upstreams):
    if len(query) < 12 or len(query) > 65535 or query[2] & 0x80:
        raise ValueError('Invalid DNS query')
    failure = minimal_reply(query, rcode=2)
    for upstream in upstreams:
        try:
            with socket.create_connection((upstream, 53), timeout=3) as conn:
                conn.sendall(struct.pack('!H', len(query)) + query)
                size = struct.unpack('!H', read_exact(conn, 2))[0]
                answer = read_exact(conn, size)
                if len(answer) >= 12 and answer[:2] == query[:2] and answer[2] & 0x80:
                    return answer
        except OSError:
            continue
    # SERVFAIL with no records. Never fall back to public DNS.
    return failure


class UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    address, dns = sys.argv[1:3]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5353
    upstreams = [x for x in dns.split(',') if x]

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            try:
                answer = forward(query, upstreams)
                if len(answer) > 512:
                    answer = minimal_reply(query, truncated=True)
                sock.sendto(answer, self.client_address)
            except (OSError, ValueError):
                pass

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                while True:
                    size = struct.unpack('!H', read_exact(self.request, 2))[0]
                    answer = forward(read_exact(self.request, size), upstreams)
                    self.request.sendall(struct.pack('!H', len(answer)) + answer)
            except (OSError, ValueError):
                pass

    udp = UDPServer((address, port), UDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    TCPServer((address, port), TCP).serve_forever()


if __name__ == '__main__':
    main()
