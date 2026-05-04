"""
parse_dns.py — Parsing manual do protocolo DNS (RFC 1035)

Estrutura do cabeçalho DNS (fixo, 12 bytes):
  Offset  Bits  Campo
  0       16    ID — Identificador da transação
  2       1     QR — 0=Query, 1=Response
  2       4     OPCODE — tipo de query (0=QUERY, 1=IQUERY, 2=STATUS)
  2       1     AA — Authoritative Answer
  2       1     TC — Truncated
  2       1     RD — Recursion Desired
  3       1     RA — Recursion Available
  3       3     Z  — Reservado (deve ser 0)
  3       4     RCODE — Response Code (0=NoError, 3=NXDOMAIN, etc.)
  4       16    QDCOUNT — Número de questões (Question Count)
  6       16    ANCOUNT — Número de respostas (Answer Count)
  8       16    NSCOUNT — Número de registos de autoridade
  10      16    ARCOUNT — Número de registos adicionais

Após o cabeçalho: secção de Questions, seguida de Answers, Authority, Additional.

Formato de um Question:
  QNAME  (comprimento variável, terminado por byte 0x00)
  QTYPE  (2 bytes)
  QCLASS (2 bytes)

Formato de um Resource Record (RR):
  NAME   (comprimento variável, pode usar compressão por ponteiros)
  TYPE   (2 bytes)
  CLASS  (2 bytes)
  TTL    (4 bytes)
  RDLENGTH (2 bytes)
  RDATA  (RDLENGTH bytes)
"""

import struct
import socket


DNS_HEADER_LEN = 12  # O cabeçalho DNS tem sempre 12 bytes

# Tipos de registos DNS mais comuns
DNS_TYPES = {
    1:   "A",
    2:   "NS",
    5:   "CNAME",
    6:   "SOA",
    12:  "PTR",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    33:  "SRV",
    255: "ANY",
}

# Códigos de resposta DNS
DNS_RCODES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
}


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Extrai um nome DNS do buffer 'data' a partir de 'offset'.
    Suporta compressão por ponteiros (RFC 1035 secção 4.1.4).

    Returns:
        (nome_completo, novo_offset_após_o_nome)
    """
    labels = []
    max_jumps = 10  # Limite para evitar loops infinitos com ponteiros circulares
    jumps = 0
    original_offset = offset
    jumped = False

    while offset < len(data):
        length = data[offset]

        if length == 0:
            # Fim do nome (byte terminador)
            offset += 1
            break

        elif (length & 0xC0) == 0xC0:
            # Ponteiro de compressão: 2 bytes, com os 2 bits altos a 1
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2  # Avançar no fluxo principal
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
        else:
            # Label normal: 'length' bytes a seguir
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    name = ".".join(labels) + "." if labels else "."

    # Se houve salto, o offset "real" foi capturado antes do ponteiro
    end_offset = original_offset if jumped else offset
    return name, end_offset


def _parse_question(data: bytes, offset: int) -> tuple[dict, int]:
    """
    Extrai uma entrada da secção Question a partir de 'offset'.

    Returns:
        (dicionário com qname, qtype, qclass, offset após a question)
    """
    qname, offset = _parse_name(data, offset)

    if offset + 4 > len(data):
        return {"qname": qname, "qtype": 0, "qclass": 0}, offset

    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4

    return {
        "qname":  qname,
        "qtype":  qtype,
        "qtype_name": DNS_TYPES.get(qtype, f"Type{qtype}"),
        "qclass": qclass,
    }, offset


def _parse_rr(data: bytes, offset: int) -> tuple[dict | None, int]:
    """
    Extrai um Resource Record a partir de 'offset'.

    Returns:
        (dicionário com name, type, class, ttl, rdata; offset após o RR)
    """
    name, offset = _parse_name(data, offset)

    if offset + 10 > len(data):
        return None, offset

    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10

    if offset + rdlength > len(data):
        return None, offset

    rdata_raw = data[offset:offset + rdlength]
    offset += rdlength

    # Interpretar o RDATA consoante o tipo
    rdata_str = _decode_rdata(rtype, rdata_raw, data)

    return {
        "name":    name,
        "type":    rtype,
        "type_name": DNS_TYPES.get(rtype, f"Type{rtype}"),
        "class":   rclass,
        "ttl":     ttl,
        "rdata":   rdata_str,
    }, offset


def _decode_rdata(rtype: int, rdata: bytes, full_msg: bytes) -> str:
    """
    Converte o RDATA para uma representação legível conforme o tipo do RR.
    """
    try:
        if rtype == 1 and len(rdata) == 4:
            # A record: endereço IPv4
            return socket.inet_ntoa(rdata)

        elif rtype == 28 and len(rdata) == 16:
            # AAAA record: endereço IPv6
            return socket.inet_ntop(socket.AF_INET6, rdata)

        elif rtype in (2, 5, 12):
            # NS, CNAME, PTR: nome DNS
            name, _ = _parse_name(full_msg, len(full_msg) - len(rdata))
            # Nota: usar offset relativo ao full_msg seria mais correto,
            # mas aqui o rdata pode conter ponteiros — parse direto é seguro:
            name, _ = _parse_name(rdata + bytes(len(full_msg)), 0)
            return name if name else rdata.hex()

        elif rtype == 15:
            # MX: preferência (2 bytes) + nome do servidor de correio
            if len(rdata) >= 2:
                preference = struct.unpack("!H", rdata[:2])[0]
                name, _ = _parse_name(rdata, 2)
                return f"pref={preference} {name}"

        elif rtype == 16:
            # TXT: sequência de strings precedidas por comprimento
            parts = []
            i = 0
            while i < len(rdata):
                l = rdata[i]
                i += 1
                parts.append(rdata[i:i + l].decode("utf-8", errors="replace"))
                i += l
            return " ".join(parts)

    except Exception:
        pass

    return rdata.hex()


def parse_dns(payload: bytes) -> dict | None:
    """
    Faz o parsing completo de uma mensagem DNS a partir do payload UDP.

    Args:
        payload: Bytes do payload UDP (começa no byte 0 do cabeçalho DNS).

    Returns:
        Dicionário com:
          - id         : Transaction ID (int)
          - qr         : 0=Query, 1=Response (int)
          - opcode     : Código de operação (int)
          - aa         : Authoritative Answer (bool)
          - tc         : Truncated (bool)
          - rd         : Recursion Desired (bool)
          - ra         : Recursion Available (bool)
          - rcode      : Response Code (int)
          - rcode_name : Nome do Response Code (str)
          - questions  : Lista de dicionários com as questions
          - answers    : Lista de dicionários com os RRs de resposta
          - summary    : Descrição legível (str)
        None se os bytes forem insuficientes.
    """
    if len(payload) < DNS_HEADER_LEN:
        return None

    # Desempacotar o cabeçalho DNS (12 bytes)
    dns_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", payload[:DNS_HEADER_LEN]
    )

    # Decodificar o campo de flags (16 bits)
    qr     = (flags >> 15) & 0x1   # Bit 15: Query/Response
    opcode = (flags >> 11) & 0xF   # Bits 14-11: Opcode
    aa     = (flags >> 10) & 0x1   # Bit 10: Authoritative Answer
    tc     = (flags >> 9)  & 0x1   # Bit 9: Truncated
    rd     = (flags >> 8)  & 0x1   # Bit 8: Recursion Desired
    ra     = (flags >> 7)  & 0x1   # Bit 7: Recursion Available
    rcode  = flags & 0xF           # Bits 3-0: Response Code

    rcode_name = DNS_RCODES.get(rcode, f"RCODE{rcode}")

    offset = DNS_HEADER_LEN

    # Extrair questões
    questions = []
    for _ in range(qdcount):
        if offset >= len(payload):
            break
        q, offset = _parse_question(payload, offset)
        questions.append(q)

    # Extrair respostas (Answer section)
    answers = []
    for _ in range(ancount):
        if offset >= len(payload):
            break
        rr, offset = _parse_rr(payload, offset)
        if rr:
            answers.append(rr)

    # Construir sumário legível
    if qr == 0:
        # Query
        qname = questions[0]["qname"] if questions else "?"
        qtype = questions[0].get("qtype_name", "?") if questions else "?"
        summary = f"DNS Query | {qname} ({qtype})"
    else:
        # Response
        qname = questions[0]["qname"] if questions else "?"
        if answers:
            rdata_list = ", ".join(a["rdata"] for a in answers)
            summary = f"DNS Response | {qname} -> {rdata_list}"
        else:
            summary = f"DNS Response | {qname} [{rcode_name}]"

    return {
        "id":        dns_id,
        "qr":        qr,
        "opcode":    opcode,
        "aa":        bool(aa),
        "tc":        bool(tc),
        "rd":        bool(rd),
        "ra":        bool(ra),
        "rcode":     rcode,
        "rcode_name": rcode_name,
        "qdcount":   qdcount,
        "ancount":   ancount,
        "questions": questions,
        "answers":   answers,
        "summary":   summary,
    }