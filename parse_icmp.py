"""
parse_icmp.py — Parsing manual do protocolo ICMP (RFC 792)

Estrutura do cabeçalho ICMP (mínimo 8 bytes):
  Offset  Tamanho  Campo
  0       1        Type — tipo da mensagem ICMP
  1       1        Code — sub-tipo da mensagem
  2       2        Checksum
  4       4        Dados variáveis conforme o Type/Code

Para Echo Request (Type=8) e Echo Reply (Type=0):
  4       2        Identifier (ID)
  6       2        Sequence Number (Seq)
  8+               Dados (payload do ping)

Para Destination Unreachable (Type=3):
  4       4        Unused (zeros)
  8+               Cabeçalho IP original + primeiros 8 bytes do datagrama que causou o erro

Para Time Exceeded (Type=11):
  4       4        Unused (zeros)
  8+               Cabeçalho IP original + primeiros 8 bytes do datagrama
"""

import struct


ICMP_MIN_HEADER_LEN = 8

# Mapeamento de tipos ICMP para nomes legíveis
ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    9:  "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

# Códigos para Destination Unreachable (Type=3)
ICMP_UNREACHABLE_CODES = {
    0: "Net Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
}

# Códigos para Time Exceeded (Type=11)
ICMP_TIME_EXCEEDED_CODES = {
    0: "TTL Exceeded in Transit",
    1: "Fragment Reassembly Time Exceeded",
}


def parse_icmp(payload: bytes) -> dict | None:
    """
    Faz o parsing do cabeçalho ICMP a partir do payload recebido após o IPv4.

    Args:
        payload: Bytes do payload IP (começa no byte 0 do cabeçalho ICMP).

    Returns:
        Dicionário com:
          - type      : Tipo ICMP (int)
          - type_name : Nome do tipo (str)
          - code      : Código ICMP (int)
          - code_name : Nome do código, se aplicável (str)
          - checksum  : Checksum (int)
          - identifier: ID (int) — apenas para Echo Request/Reply
          - sequence  : Número de sequência (int) — apenas para Echo Request/Reply
          - summary   : Descrição legível da mensagem (str)
        None se os bytes forem insuficientes.
    """
    if len(payload) < ICMP_MIN_HEADER_LEN:
        return None

    # Os primeiros 4 bytes são sempre: Type, Code, Checksum
    icmp_type, icmp_code, checksum = struct.unpack("!BBH", payload[:4])

    type_name = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")

    result = {
        "type":       icmp_type,
        "type_name":  type_name,
        "code":       icmp_code,
        "code_name":  "",
        "checksum":   checksum,
        "identifier": None,
        "sequence":   None,
        "summary":    "",
    }

    if icmp_type in (0, 8):
        # Echo Request / Echo Reply — bytes 4-5: Identifier, bytes 6-7: Sequence
        identifier, sequence = struct.unpack("!HH", payload[4:8])
        result["identifier"] = identifier
        result["sequence"]   = sequence
        result["summary"] = f"{type_name} | id={identifier} seq={sequence}"

    elif icmp_type == 3:
        # Destination Unreachable
        code_name = ICMP_UNREACHABLE_CODES.get(icmp_code, f"code={icmp_code}")
        result["code_name"] = code_name
        result["summary"]   = f"{type_name} | {code_name}"

    elif icmp_type == 11:
        # Time Exceeded
        code_name = ICMP_TIME_EXCEEDED_CODES.get(icmp_code, f"code={icmp_code}")
        result["code_name"] = code_name
        result["summary"]   = f"{type_name} | {code_name}"

    elif icmp_type == 5:
        # Redirect — bytes 4-7 contêm o IP do gateway sugerido
        import socket
        gateway_ip = socket.inet_ntoa(payload[4:8])
        result["summary"] = f"Redirect | gateway={gateway_ip} code={icmp_code}"

    else:
        result["summary"] = f"{type_name} | code={icmp_code}"

    return result