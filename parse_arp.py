"""
parse_arp.py — Parsing manual do protocolo ARP (RFC 826)

Estrutura do cabeçalho ARP (28 bytes para IPv4 sobre Ethernet):
  Offset  Tamanho  Campo
  0       2        Hardware Type (HTYPE)  — 0x0001 = Ethernet
  2       2        Protocol Type (PTYPE)  — 0x0800 = IPv4
  4       1        Hardware Address Length (HLEN) — 6 para MAC
  5       1        Protocol Address Length (PLEN) — 4 para IPv4
  6       2        Operation (OP) — 1 = Request, 2 = Reply
  8       6        Sender Hardware Address (SHA) — MAC do emissor
  14      4        Sender Protocol Address (SPA) — IP do emissor
  18      6        Target Hardware Address (THA) — MAC do alvo
  24      4        Target Protocol Address (TPA) — IP do alvo

Total: 28 bytes (para Ethernet/IPv4)
"""

import struct
import socket


ARP_HEADER_LEN = 28  # Para Ethernet + IPv4

ARP_OPS = {
    1: "ARP Request",
    2: "ARP Reply",
    3: "RARP Request",
    4: "RARP Reply",
}


def _mac_to_str(raw: bytes) -> str:
    """Converte 6 bytes de MAC para string legível."""
    return ":".join(f"{b:02x}" for b in raw)


def _ip_to_str(raw: bytes) -> str:
    """Converte 4 bytes de endereço IPv4 para string legível (ex: '192.168.1.1')."""
    return socket.inet_ntoa(raw)


def parse_arp(payload: bytes) -> dict | None:
    """
    Faz o parsing do cabeçalho ARP a partir do payload recebido após o Ethernet.

    Args:
        payload: Bytes do payload Ethernet (começa no byte 0 do ARP).

    Returns:
        Dicionário com:
          - htype    : Hardware type (int)
          - ptype    : Protocol type (int)
          - hlen     : Hardware address length (int)
          - plen     : Protocol address length (int)
          - op       : Operação numérica (int)
          - op_name  : Nome da operação (str)
          - sha      : Sender Hardware Address / MAC de origem (str)
          - spa      : Sender Protocol Address / IP de origem (str)
          - tha      : Target Hardware Address / MAC de destino (str)
          - tpa      : Target Protocol Address / IP de destino (str)
          - summary  : Descrição legível da mensagem ARP (str)
        None se os bytes forem insuficientes ou o formato não for Ethernet/IPv4.
    """
    if len(payload) < ARP_HEADER_LEN:
        return None

    # Desempacotar os primeiros 8 bytes (campos fixos do cabeçalho ARP)
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", payload[:8])

    # Suportamos apenas Ethernet (htype=1) + IPv4 (ptype=0x0800)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None

    # Extrair os endereços de hardware e protocolo manualmente por offset
    sha = _mac_to_str(payload[8:14])     # Sender MAC
    spa = _ip_to_str(payload[14:18])     # Sender IP
    tha = _mac_to_str(payload[18:24])    # Target MAC
    tpa = _ip_to_str(payload[24:28])     # Target IP

    op_name = ARP_OPS.get(op, f"ARP op={op}")

    # Construir sumário legível
    if op == 1:
        summary = f"ARP Request | Who has {tpa}? Tell {spa}"
    elif op == 2:
        summary = f"ARP Reply | {spa} is at {sha}"
    else:
        summary = f"{op_name} | {spa} -> {tpa}"

    return {
        "htype":   htype,
        "ptype":   ptype,
        "hlen":    hlen,
        "plen":    plen,
        "op":      op,
        "op_name": op_name,
        "sha":     sha,
        "spa":     spa,
        "tha":     tha,
        "tpa":     tpa,
        "summary": summary,
    }