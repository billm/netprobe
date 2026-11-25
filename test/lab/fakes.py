"""Canned responders for protocols the lab has no real server for.

TCP 21 and 587: FTP and SMTP greetings. TCP 25: an SMTP server that answers VRFY
for root only and accepts any recipient (an open relay). UDP 137: NetBIOS node status. UDP 623: IPMI channel auth
capabilities. UDP 1434: SQL Server Browser instance list.
"""

import socket
import struct
import threading


def nbns_reply(query: bytes) -> bytes:
    names = [
        (b"LABHOST", 0x00, 0x0400),
        (b"WORKGROUP", 0x00, 0x8400),
        (b"LABHOST", 0x20, 0x0400),
    ]
    rdata = bytes([len(names)])
    for name, suffix, flags in names:
        rdata += name.ljust(15) + bytes([suffix]) + struct.pack(">H", flags)
    rdata += bytes.fromhex("02420a1e630a") + bytes(40)
    header = query[:2] + bytes.fromhex("8400 0000 0001 0000 0000")
    qname = query[12:46]
    return header + qname + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata


def ipmi_reply(query: bytes) -> bytes:
    rmcp = bytes.fromhex("0600ff07")
    session = bytes.fromhex("00 00000000 00000000 10")
    message = bytes.fromhex("8118 67 20 00 38 00 01 97 05 03 000000 00 00")
    return rmcp + session + message


def mssql_reply(query: bytes) -> bytes:
    body = (
        b"ServerName;LABSQL;InstanceName;MSSQLSERVER;IsClustered;No;"
        b"Version;15.0.2000.5;tcp;1433;;"
    )
    return b"\x05" + struct.pack("<H", len(body)) + body


def udp_server(port: int, handler) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, addr = sock.recvfrom(4096)
        sock.sendto(handler(data), addr)


def banner_server(port: int, banner: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        conn.sendall(banner)
        conn.close()


SMTP_REPLIES = {
    "EHLO": "250-netprobe-lab\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 SIZE 10240000",
    "EXPN": "502 5.5.1 EXPN not implemented",
    "MAIL": "250 2.1.0 Ok",
    "RCPT": "250 2.1.5 Ok",
    "RSET": "250 2.0.0 Ok",
    "QUIT": "221 2.0.0 Bye",
}


def smtp_session(conn: socket.socket) -> None:
    with conn, conn.makefile("rb") as lines:
        conn.sendall(b"220 netprobe-lab ESMTP fake\r\n")
        for raw in lines:
            command = raw.decode("ascii", "replace").strip()
            verb = command.split(" ")[0].upper()
            if verb == "VRFY":
                reply = (
                    "252 2.0.0 root"
                    if command.endswith(" root")
                    else "550 5.1.1 unknown"
                )
            else:
                reply = SMTP_REPLIES.get(verb, "500 5.5.2 unrecognized")
            conn.sendall(reply.encode("ascii") + b"\r\n")
            if verb == "QUIT":
                return


def smtp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 25))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=smtp_session, args=(conn,), daemon=True).start()


def main() -> None:
    for port, handler in ((137, nbns_reply), (623, ipmi_reply), (1434, mssql_reply)):
        threading.Thread(target=udp_server, args=(port, handler), daemon=True).start()
    threading.Thread(target=smtp_server, daemon=True).start()
    smtp = (587, b"220 netprobe-lab ESMTP ready\r\n")
    threading.Thread(target=banner_server, args=smtp, daemon=True).start()
    banner_server(21, b"220 netprobe-lab FTP ready\r\n")


if __name__ == "__main__":
    main()
