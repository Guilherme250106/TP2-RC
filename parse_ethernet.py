"""
parse_ethernet.py — Parsing manual da camada Ethernet (IEEE 802.3)

Estrutura do cabeçalho Ethernet (14 bytes):
  Offset  Tamanho  Campo
  0       6        MAC de destino
  6       6        MAC de origem
  12      2        EtherType (identifica o protocolo de camada 3)

EtherTypes relevantes:
  0x0800 → IPv4
  0x0806 → ARP
  0x86DD → IPv6
"""

import struct


# Tamanho mínimo do cabeçalho Ethernet
ETHERNET_HEADER_LEN = 14

# Mapeamento de EtherTypes conhecidos
ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
    0x0835: "RARP",
}


def _mac_to_str(raw: bytes) -> str:
    """Converte 6 bytes de endereço MAC para string legível (ex: 'aa:bb:cc:dd:ee:ff')."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(raw_bytes: bytes) -> dict | None:
    """
    Faz o parsing do cabeçalho Ethernet a partir dos bytes raw do pacote.

    Args:
        raw_bytes: Bytes completos do pacote (desde o início do frame Ethernet).

    Returns:
        Dicionário com:
          - dst_mac   : MAC de destino (str)
          - src_mac   : MAC de origem (str)
          - ethertype : Valor numérico do EtherType (int)
          - proto_name: Nome legível do EtherType (str)
          - payload   : Bytes do payload (tudo após os 14 bytes do cabeçalho)
        None se os bytes forem insuficientes.
    """
    if len(raw_bytes) < ETHERNET_HEADER_LEN:
        return None

    # '!' = big-endian (network byte order)
    # '6s' = 6 bytes (MAC destino), '6s' = 6 bytes (MAC origem), 'H' = unsigned short 2 bytes (EtherType)
    dst_mac_raw, src_mac_raw, ethertype = struct.unpack("!6s6sH", raw_bytes[:ETHERNET_HEADER_LEN])

    return {
        "dst_mac":    _mac_to_str(dst_mac_raw),
        "src_mac":    _mac_to_str(src_mac_raw),
        "ethertype":  ethertype,
        "proto_name": ETHERTYPES.get(ethertype, f"0x{ethertype:04x}"),
        "payload":    raw_bytes[ETHERNET_HEADER_LEN:],
    }