"""
parser.py — Módulo de parsing e identificação de protocolos
Analisa pacotes Scapy e extrai informação relevante de cada protocolo.

Protocolos suportados:
  Camada 2: Ethernet, ARP
  Camada 3: IPv4, IPv6, ICMP, ICMPv6
  Camada 4: TCP, UDP
  Camada 7: DNS, HTTP, DHCP
"""

from datetime import datetime
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.packet import Raw

# IPv6 e DNS/DHCP importados com fallback (podem falhar em ambientes sem IPv6)
try:
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
    _HAS_IPV6 = True
except Exception:
    _HAS_IPV6 = False
    IPv6 = None
    ICMPv6EchoRequest = None
    ICMPv6EchoReply = None

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False
    DNS = None

try:
    from scapy.layers.dhcp import DHCP, BOOTP
    _HAS_DHCP = True
except Exception:
    _HAS_DHCP = False
    DHCP = None
    BOOTP = None


# =============================================================================
# CONSTANTES DE APOIO
# =============================================================================

# Mapeamento dos tipos ARP para descrição legível
ARP_OP = {1: "ARP Request", 2: "ARP Reply"}

# Mapeamento dos tipos/códigos ICMP mais comuns
ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
}

# Mapeamento das flags TCP (bitmask)
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
}

# Portas TCP/UDP associadas a protocolos aplicacionais conhecidos
WELL_KNOWN_PORTS = {
    80:   "HTTP",
    443:  "HTTPS",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    123:  "NTP",
}

# Tipos de mensagens DHCP (opção 53)
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


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def _flags_str(flags) -> str:
    """Converte flags TCP (objeto Scapy) numa string legível, ex: 'SYN ACK'."""
    result = []
    for char, name in TCP_FLAGS.items():
        if char in str(flags):
            result.append(name)
    return " ".join(result) if result else "NONE"


def _port_hint(port: int) -> str:
    """Devolve o nome do protocolo associado a uma porta, ou a porta em si."""
    return WELL_KNOWN_PORTS.get(port, str(port))


def _get_dhcp_msg_type(dhcp_layer) -> str:
    """Extrai o tipo de mensagem DHCP da camada DHCP do Scapy."""
    if dhcp_layer is None:
        return "DHCP"
    for opt in dhcp_layer.options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return DHCP_MSG_TYPES.get(opt[1], f"DHCP Type {opt[1]}")
    return "DHCP"


# =============================================================================
# FUNÇÕES DE PARSING POR PROTOCOLO
# =============================================================================

def _parse_arp(pkt, base: dict) -> dict:
    """
    Analisa a camada ARP.
    ARP (Address Resolution Protocol) mapeia endereços IP em endereços MAC.
    Campos principais: op (1=request, 2=reply), psrc/pdst (IPs), hwsrc/hwdst (MACs).
    """
    arp = pkt[ARP]
    base["protocol"] = "ARP"
    base["src_mac"]  = arp.hwsrc
    base["dst_mac"]  = arp.hwdst
    base["src_ip"]   = arp.psrc
    base["dst_ip"]   = arp.pdst
    base["summary"]  = ARP_OP.get(arp.op, f"ARP op={arp.op}") + \
                       f" | {arp.psrc} -> {arp.pdst}"
    return base


def _parse_icmp(pkt, base: dict) -> dict:
    """
    Analisa a camada ICMP (sobre IPv4).
    ICMP é usado para diagnóstico de rede (ping, erros de routing, etc.).
    Campos principais: type (tipo da mensagem), code, id, seq.
    """
    icmp = pkt[ICMP]
    base["protocol"] = "ICMP"
    type_str = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")

    # Para Echo Request/Reply, incluímos id e sequência
    if icmp.type in (0, 8):
        base["summary"] = f"{type_str} | id={icmp.id} seq={icmp.seq}"
    else:
        base["summary"] = f"{type_str} | code={icmp.code}"
    return base


def _parse_dns(pkt, base: dict) -> dict:
    """
    Analisa a camada DNS (tipicamente sobre UDP porta 53).
    DNS resolve nomes de domínio em endereços IP.
    QR=0 significa Query, QR=1 significa Response.
    """
    dns = pkt[DNS]
    base["protocol"] = "DNS"
    is_response = dns.qr == 1

    if is_response:
        # Resposta: listar os registos devolvidos
        answers = []
        for i in range(dns.ancount):
            rr = dns.an[i]
            if hasattr(rr, "rdata"):
                answers.append(str(rr.rdata))
        answers_str = ", ".join(answers) if answers else "sem registos"
        # Nome da query (se disponível)
        qname = dns.qd.qname.decode() if dns.qd else "?"
        base["summary"] = f"DNS Response | {qname} -> {answers_str}"
    else:
        # Query: mostrar o nome pedido
        qname = dns.qd.qname.decode() if dns.qd else "?"
        base["summary"] = f"DNS Query | {qname}"

    return base


def _parse_dhcp(pkt, base: dict) -> dict:
    """
    Analisa a camada DHCP (sobre UDP portas 67/68).
    DHCP atribui endereços IP automaticamente.
    Fases principais: Discover -> Offer -> Request -> ACK (DORA).
    """
    dhcp = pkt[DHCP] if DHCP in pkt else None
    bootp = pkt[BOOTP] if BOOTP in pkt else None
    msg_type = _get_dhcp_msg_type(dhcp)
    base["protocol"] = "DHCP"

    # O BOOTP contém o IP proposto (yiaddr) e o IP do cliente (ciaddr)
    if bootp:
        yiaddr = bootp.yiaddr  # IP oferecido/atribuído
        ciaddr = bootp.ciaddr  # IP do cliente (se já tem)
        xid    = hex(bootp.xid)  # Transaction ID (identifica a sessão DORA)
        base["summary"] = f"{msg_type} | xid={xid} offered={yiaddr} client={ciaddr}"
    else:
        base["summary"] = msg_type

    return base


def _parse_http(pkt, base: dict) -> dict:
    """
    Analisa tráfego HTTP (TCP porta 80) a partir do payload Raw.
    HTTP é um protocolo de texto — tentamos ler a primeira linha do pedido/resposta.
    """
    base["protocol"] = "TCP/HTTP"
    try:
        payload = bytes(pkt[Raw].load).decode("utf-8", errors="replace")
        first_line = payload.split("\r\n")[0][:80]  # Limite de 80 chars
        base["summary"] = f"HTTP | {first_line}"
    except Exception:
        base["summary"] = "HTTP (payload ilegível)"
    return base


def _parse_tcp(pkt, base: dict) -> dict:
    """
    Analisa a camada TCP.
    TCP é orientado à conexão — usa flags (SYN/ACK/FIN/RST) para gerir o ciclo de vida.
    Campos principais: sport, dport, seq, ack, flags.
    """
    tcp = pkt[TCP]
    flags = _flags_str(tcp.flags)
    src_port = tcp.sport
    dst_port = tcp.dport

    # Verificar se é HTTP (porta 80) e há payload
    if (src_port == 80 or dst_port == 80) and Raw in pkt:
        return _parse_http(pkt, base)

    # Protocolo aplicacional pela porta (se conhecido)
    app_proto = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port, "")
    proto_label = f"TCP/{app_proto}" if app_proto else "TCP"

    base["protocol"] = proto_label
    base["summary"]  = (
        f"{flags} | "
        f"{src_port} -> {dst_port} | "
        f"seq={tcp.seq} ack={tcp.ack}"
    )
    return base


def _parse_udp(pkt, base: dict) -> dict:
    """
    Analisa a camada UDP.
    UDP não é orientado à conexão — simples, rápido, sem garantias de entrega.
    DHCP e DNS usam UDP tipicamente.
    """
    udp = pkt[UDP]

    # Sub-protocolos sobre UDP
    if _HAS_DNS and DNS in pkt:
        base = _parse_dns(pkt, base)
        return base

    if _HAS_DHCP and (DHCP in pkt or BOOTP in pkt):
        base = _parse_dhcp(pkt, base)
        return base

    # UDP genérico
    app_proto = WELL_KNOWN_PORTS.get(udp.dport) or WELL_KNOWN_PORTS.get(udp.sport, "")
    proto_label = f"UDP/{app_proto}" if app_proto else "UDP"

    base["protocol"] = proto_label
    base["summary"]  = f"{udp.sport} -> {udp.dport} | len={udp.len}"
    return base


def _parse_ipv6(pkt, base: dict) -> dict:
    """
    Analisa a camada IPv6.
    Extrai endereços de origem/destino e identifica o próximo protocolo.
    """
    ip6 = pkt[IPv6]
    base["src_ip"] = ip6.src
    base["dst_ip"] = ip6.dst

    if TCP in pkt:
        base = _parse_tcp(pkt, base)
        base["protocol"] = "IPv6/" + base.get("protocol", "TCP")
    elif UDP in pkt:
        base = _parse_udp(pkt, base)
        base["protocol"] = "IPv6/" + base.get("protocol", "UDP")
    elif ICMPv6EchoRequest in pkt:
        base["protocol"] = "ICMPv6"
        base["summary"] = "ICMPv6 Echo Request"
    elif ICMPv6EchoReply in pkt:
        base["protocol"] = "ICMPv6"
        base["summary"] = "ICMPv6 Echo Reply"
    else:
        base["protocol"] = "IPv6"
        base["summary"] = f"IPv6 nh={ip6.nh}"

    return base


def _parse_ipv4(pkt, base: dict) -> dict:
    """
    Analisa a camada IPv4.
    Extrai endereços IP e delega para o protocolo de camada superior.
    """
    ip = pkt[IP]
    base["src_ip"] = ip.src
    base["dst_ip"] = ip.dst

    if ICMP in pkt:
        base = _parse_icmp(pkt, base)
    elif TCP in pkt:
        base = _parse_tcp(pkt, base)
    elif UDP in pkt:
        base = _parse_udp(pkt, base)
    else:
        base["protocol"] = "IPv4"
        base["summary"]  = f"Proto={ip.proto}"

    return base


# =============================================================================
# FUNÇÃO PRINCIPAL DE PARSING
# =============================================================================

def parse_packet(pkt, iface: str = "?") -> dict | None:
    """
    Ponto de entrada principal: recebe um pacote Scapy e devolve um dicionário
    com toda a informação relevante extraída.

    Args:
        pkt:        Pacote Scapy capturado.
        iface (str): Nome da interface de rede onde foi capturado.

    Returns:
        dict com os campos: timestamp, interface, protocol, src_mac, dst_mac,
                            src_ip, dst_ip, size, summary.
        None se o pacote não tiver camada Ethernet (raro, mas possível).
    """
    if Ether not in pkt:
        return None  # Ignorar pacotes sem cabeçalho Ethernet

    eth = pkt[Ether]

    # Estrutura base — campos comuns a todos os pacotes
    base = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "interface": iface,
        "protocol":  "Ethernet",   # será sobrescrito pelas camadas superiores
        "src_mac":   eth.src,
        "dst_mac":   eth.dst,
        "src_ip":    "",
        "dst_ip":    "",
        "size":      len(pkt),
        "summary":   "",
    }

    # Delegar parsing para a camada de rede correta
    if ARP in pkt:
        base = _parse_arp(pkt, base)
    elif IP in pkt:
        base = _parse_ipv4(pkt, base)
    elif _HAS_IPV6 and IPv6 is not None and IPv6 in pkt:
        base = _parse_ipv6(pkt, base)
    else:
        # Protocolo de camada 2 desconhecido (ex: CDP, STP, etc.)
        base["protocol"] = f"L2 (ethertype={hex(eth.type)})"
        base["summary"]  = "Protocolo não identificado"

    return base
