"""
parse_udp.py — Parsing manual do cabeçalho UDP (RFC 768)

Estrutura do cabeçalho UDP (fixo, sempre 8 bytes):
  Offset  Tamanho  Campo
  0       2        Source Port
  2       2        Destination Port
  4       2        Length (cabeçalho + dados, em bytes; mínimo 8)
  6       2        Checksum (opcional em IPv4, obrigatório em IPv6)

UDP é sem ligação e sem garantias — não há SYN/ACK, sequências nem retransmissão.
O payload começa sempre no byte 8.
"""

import struct

UDP_HEADER_LEN = 8  # O cabeçalho UDP tem sempre exatamente 8 bytes

# Portas UDP associadas a protocolos aplicacionais conhecidos
WELL_KNOWN_PORTS = {
    53:  "DNS",
    67:  "DHCP",    # Servidor DHCP
    68:  "DHCP",    # Cliente DHCP
    123: "NTP",
    161: "SNMP",
    162: "SNMP Trap",
    514: "Syslog",
    5353: "mDNS",
}


def parse_udp(payload: bytes) -> dict | None:
    """
    Faz o parsing do cabeçalho UDP a partir do payload recebido após o IPv4/IPv6.

    Args:
        payload: Bytes do payload IP (começa no byte 0 do cabeçalho UDP).

    Returns:
        Dicionário com:
          - src_port     : Porta de origem (int)
          - dst_port     : Porta de destino (int)
          - length       : Comprimento total UDP (cabeçalho + dados) em bytes (int)
          - checksum     : Checksum (int)
          - app_proto    : Protocolo aplicacional identificado pela porta (str)
          - proto_label  : Label do protocolo (str), ex: 'UDP/DNS'
          - inner_payload: Bytes do payload UDP (para camada de aplicação)
          - summary      : Descrição legível (str)
        None se os bytes forem insuficientes.
    """
    if len(payload) < UDP_HEADER_LEN:
        return None

    # Desempacotar os 8 bytes fixos do cabeçalho UDP
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", payload[:UDP_HEADER_LEN])

    # O payload UDP começa após os 8 bytes do cabeçalho
    inner_payload = payload[UDP_HEADER_LEN:]

    # Identificar protocolo aplicacional pela porta
    app_proto = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port, "")
    proto_label = f"UDP/{app_proto}" if app_proto else "UDP"

    summary = f"{src_port} -> {dst_port} | len={length}"

    return {
        "src_port":      src_port,
        "dst_port":      dst_port,
        "length":        length,
        "checksum":      checksum,
        "app_proto":     app_proto,
        "proto_label":   proto_label,
        "inner_payload": inner_payload,
        "summary":       summary,
    }