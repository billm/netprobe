"""Canned responders for protocols the lab has no real server for.

TCP 21: FTP greeting. UDP 137: NetBIOS node status. UDP 623: IPMI channel auth
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


def ftp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 21))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        conn.sendall(b"220 netprobe-lab FTP ready\r\n")
        conn.close()


def main() -> None:
    for port, handler in ((137, nbns_reply), (623, ipmi_reply), (1434, mssql_reply)):
        threading.Thread(target=udp_server, args=(port, handler), daemon=True).start()
    ftp_server()


if __name__ == "__main__":
    main()
