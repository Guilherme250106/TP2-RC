"""
parse_ipv6.py — Parsing manual do cabeçalho IPv6 (RFC 8200)
Faz parsing do cabeçalho base IPv6 (40 bytes). Não faz parsing completo de
todas as extensões; devolve next_header e o payload restante para processamento posterior.
"""
import struct
import socket

IPV6_HEADER_LEN = 40

# Next Header (alguns valores comuns)
NEXT_HEADERS = {
    0:  "Hop-by-Hop",
    6:  "TCP",
    17: "UDP",
    43: "Routing",
    44: "Fragment",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    60: "Destination Options",
}

def _ip6_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return "::"

def parse_ipv6(payload: bytes) -> dict | None:
    """
    Parse do cabeçalho IPv6 a partir do início do pacote IPv6.

    Retorna dicionário com:
      - version, tclass, flow_label
      - payload_len (int), next_header (int), next_header_name (str), hop_limit
      - src_ip, dst_ip (strings)
      - inner_payload: bytes após o cabeçalho base (possivelmente contendo extension headers)
      - summary (str)
    """
    if len(payload) < IPV6_HEADER_LEN:
        return None

    # 4 bytes: version(4) | traffic class(8) | flow label(20)
    first_word = struct.unpack("!I", payload[0:4])[0]
    version = (first_word >> 28) & 0xF
    tclass = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF

    payload_len = struct.unpack("!H", payload[4:6])[0]
    next_header = payload[6]
    hop_limit = payload[7]

    src = _ip6_to_str(payload[8:24])
    dst = _ip6_to_str(payload[24:40])

    inner = payload[IPV6_HEADER_LEN:]

    nh_name = NEXT_HEADERS.get(next_header, f"NH{next_header}")

    summary = f"IPv6 {src} -> {dst} nh={nh_name} len={payload_len} hl={hop_limit}"

    return {
        "version": version,
        "tclass": tclass,
        "flow_label": flow_label,
        "payload_len": payload_len,
        "next_header": next_header,
        "next_header_name": nh_name,
        "hop_limit": hop_limit,
        "src_ip": src,
        "dst_ip": dst,
        "inner_payload": inner,
        "summary": summary,
    }
