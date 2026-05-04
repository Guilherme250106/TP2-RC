"""
parse_dhcp.py — Parsing manual do protocolo DHCP (BOOTP + opções DHCP)
Baseado em RFC 2131 / RFC 951 (BOOTP)
"""
import struct
import socket

BOOTP_FIXED_LEN = 236  # tamanho fixo do cabeçalho BOOTP antes das options
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"

DHCP_MSG_TYPES = {
    1: "DHCP Discover",
    2: "DHCP Offer",
    3: "DHCP Request",
    4: "DHCP Decline",
    5: "DHCP ACK",
    6: "DHCP NAK",
    7: "DHCP Release",
    8: "DHCP Inform",
}


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntoa(raw)
    except Exception:
        return "0.0.0.0"


def parse_dhcp(payload: bytes) -> dict | None:
    """
    Faz parsing de uma mensagem BOOTP/DHCP a partir do payload UDP (começa em BOOTP.op).

    Retorna dicionário com campos relevantes ou None se inválido/curto.
    """
    if len(payload) < BOOTP_FIXED_LEN:
        return None

    # BOOTP fixed header: !BBBBIHH4s4s4s4s16s64s128s
    try:
        (
            op, htype, hlen, hops, xid, secs, flags,
            ciaddr, yiaddr, siaddr, giaddr,
            chaddr,
            sname,
            file_field
        ) = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", payload[:BOOTP_FIXED_LEN])
    except struct.error:
        return None

    # Endereços
    ci = _ip_to_str(ciaddr)
    yi = _ip_to_str(yiaddr)
    si = _ip_to_str(siaddr)
    gi = _ip_to_str(giaddr)

    # MAC: usar os primeiros 'hlen' bytes do campo chaddr
    chaddr_bytes = chaddr[:hlen] if hlen <= len(chaddr) else chaddr
    chaddr_str = _mac_to_str(chaddr_bytes)

    # Verificar cookie e options
    options: dict = {}
    dhcp_msg_type = None
    opts_offset = BOOTP_FIXED_LEN
    if len(payload) >= opts_offset + 4 and payload[opts_offset:opts_offset+4] == DHCP_MAGIC_COOKIE:
        idx = opts_offset + 4
        while idx < len(payload):
            opt = payload[idx]
            idx += 1
            if opt == 255:  # End
                break
            if opt == 0:  # Pad
                continue
            if idx >= len(payload):
                break
            opt_len = payload[idx]
            idx += 1
            if idx + opt_len > len(payload):
                break
            opt_data = payload[idx:idx+opt_len]
            idx += opt_len
            # Guardar opção de forma simples
            if opt == 53 and opt_len >= 1:
                dhcp_msg_type = DHCP_MSG_TYPES.get(opt_data[0], f"Type{opt_data[0]}")
                options["message_type"] = dhcp_msg_type
            else:
                # armazenar raw e, quando possível, valores inteiros/strings
                try:
                    if opt_len == 4:
                        options[opt] = socket.inet_ntoa(opt_data)
                    else:
                        options[opt] = opt_data.hex()
                except Exception:
                    options[opt] = opt_data.hex()

    # Summary legível
    xid_hex = f"0x{xid:08x}"
    msg = dhcp_msg_type or "DHCP"
    summary = f"{msg} xid={xid_hex} {yi} <- {ci} chaddr={chaddr_str}"

    return {
        "op": op,
        "htype": htype,
        "hlen": hlen,
        "hops": hops,
        "xid": xid,
        "secs": secs,
        "flags": flags,
        "ciaddr": ci,
        "yiaddr": yi,
        "siaddr": si,
        "giaddr": gi,
        "chaddr": chaddr_str,
        "options": options,
        "message_type": dhcp_msg_type,
        "summary": summary,
    }
