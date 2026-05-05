# ...existing code...
"""
parser.py — Módulo de parsing usando os parsers manuais (defensivo)
"""

from datetime import datetime
from scapy.layers.l2 import Ether  # apenas para checar que é um pacote L2 scapy
from scapy.packet import Packet  # tipagem mínima
import traceback

# Import dos parsers manuais — obrigatórios para este ficheiro funcionar
try:
    from parse_ethernet import parse_ethernet
    from parse_ipv4 import parse_ipv4
    from parse_ipv6 import parse_ipv6
    from parse_arp import parse_arp as parse_arp_manual
    from parse_tcp import parse_tcp as parse_tcp_manual
    from parse_udp import parse_udp as parse_udp_manual
    from parse_dns import parse_dns as parse_dns_manual
    from parse_dhcp import parse_dhcp as parse_dhcp_manual
    from parse_icmp import parse_icmp as parse_icmp_manual
    _HAS_MANUAL = True
    _MANUAL_IMPORT_ERROR = None
except Exception as e:
    _HAS_MANUAL = False
    _MANUAL_IMPORT_ERROR = e

# =============================================================================
# FUNÇÃO PRINCIPAL DE PARSING (USANDO PARSERS MANUAIS)
# =============================================================================

def _safe_call(fn, *args, **kwargs):
    """Chama fn de forma segura; captura exceções e devolve None em caso de erro."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        # não propagar exceções de parsing para o sniffer
        # para debug, poderíamos registar traceback noutro lugar
        return None

def parse_packet(pkt: Packet, iface: str = "?") -> dict | None:
    """
    Recebe um pacote Scapy e devolve um dicionário com informação extraída
    usando os parsers manuais (parse_*.py). Não usa as funções de parsing do Scapy.
    Em caso de erro interno, retorna um resumo mínimo em vez de lançar.
    """
    if not _HAS_MANUAL:
        raise RuntimeError("Parsers manuais não disponíveis: " + repr(_MANUAL_IMPORT_ERROR))

    # verificar que é um pacote Scapy com camada L2 (Ethernet)
    if not isinstance(pkt, Packet) or Ether not in pkt:
        return None

    raw = bytes(pkt)

    eth = _safe_call(parse_ethernet, raw)
    if not eth:
        # devolve resumo L2 mínimo
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "interface": iface,
            "protocol": "Ethernet",
            "src_mac": "",
            "dst_mac": "",
            "src_ip": "",
            "dst_ip": "",
            "size": len(raw),
            "summary": "Ethernet parsing failed",
        }

    base = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "interface": iface,
        "protocol": "Ethernet",
        "src_mac": eth.get("src_mac", ""),
        "dst_mac": eth.get("dst_mac", ""),
        "src_ip": "",
        "dst_ip": "",
        "size": len(raw),
        "summary": "",
    }

    ethertype = eth.get("ethertype")
    payload = eth.get("payload", b"")

    # ARP
    if ethertype == 0x0806:
        arp = _safe_call(parse_arp_manual, payload)
        if arp:
            base.update({
                "protocol": "ARP",
                "summary": arp.get("summary", ""),
                "src_mac": arp.get("sha", base["src_mac"]),
                "dst_mac": arp.get("tha", base["dst_mac"]),
                "src_ip": arp.get("spa", ""),
                "dst_ip": arp.get("tpa", ""),
            })
        else:
            base["summary"] = "ARP parsing failed"
        return base

    # IPv4
    if ethertype == 0x0800:
        ip = _safe_call(parse_ipv4, payload)
        if not ip:
            base["summary"] = "IPv4 parsing failed"
            return base
        base["src_ip"] = ip.get("src_ip", "")
        base["dst_ip"] = ip.get("dst_ip", "")
        proto = ip.get("proto")

        if proto == 1:  # ICMP
            icmp = _safe_call(parse_icmp_manual, ip.get("inner_payload", b""))
            if icmp:
                base.update({
                    "protocol": "IPv4/ICMP",
                    "summary": icmp.get("summary", "")
                })
            else:
                base.update({"protocol": "IPv4/ICMP", "summary": "ICMP parsing failed"})
            return base

        if proto == 6:  # TCP
            tcp = _safe_call(parse_tcp_manual, ip.get("inner_payload", b""))
            if tcp:
                base.update({
                    "protocol": f"TCP/{tcp.get('app_proto','')}" if tcp.get("app_proto") else "TCP",
                    "summary": tcp.get("summary",""),
                    "src_port": tcp.get("src_port"),
                    "dst_port": tcp.get("dst_port"),
                })
            else:
                base.update({"protocol": "TCP", "summary": "TCP parsing failed"})
            return base

        if proto == 17:  # UDP
            udp = _safe_call(parse_udp_manual, ip.get("inner_payload", b""))
            if not udp:
                base.update({"protocol": "UDP", "summary": "UDP parsing failed"})
                return base
            app = udp.get("app_proto")
            base.update({
                "protocol": f"UDP/{app}" if app else "UDP",
                "summary": udp.get("summary",""),
                "src_port": udp.get("src_port"),
                "dst_port": udp.get("dst_port"),
            })
            if app == "DNS":
                dns = _safe_call(parse_dns_manual, udp.get("inner_payload", b""))
                if dns:
                    base.update({"protocol":"DNS","summary":dns.get("summary","")})
            if app == "DHCP":
                dhcp = _safe_call(parse_dhcp_manual, udp.get("inner_payload", b""))
                if dhcp:
                    base["summary"] = dhcp.get("summary", base["summary"])
            return base

        base.update({
            "protocol": f"IPv4/{ip.get('proto_name', str(proto))}",
            "summary": ip.get("summary",""),
        })
        return base

    # IPv6
    if ethertype == 0x86DD:
        ip6 = _safe_call(parse_ipv6, payload)
        if not ip6:
            base["summary"] = "IPv6 parsing failed"
            return base
        base["src_ip"] = ip6.get("src_ip","")
        base["dst_ip"] = ip6.get("dst_ip","")
        nh = ip6.get("next_header")
        if nh == 6:
            tcp = _safe_call(parse_tcp_manual, ip6.get("inner_payload", b""))
            if tcp:
                base.update({"protocol": "IPv6/TCP", "summary": tcp.get("summary","")})
            else:
                base.update({"protocol": "IPv6/TCP", "summary": "TCP parsing failed"})
            return base
        if nh == 17:
            udp = _safe_call(parse_udp_manual, ip6.get("inner_payload", b""))
            if udp:
                base.update({"protocol": "IPv6/UDP", "summary": udp.get("summary","")})
            else:
                base.update({"protocol": "IPv6/UDP", "summary": "UDP parsing failed"})
            return base
        base.update({"protocol": f"IPv6/{ip6.get('next_header_name','')}", "summary": ip6.get("summary","")})
        return base

    base["protocol"] = f"L2 (ethertype={hex(ethertype) if ethertype is not None else 'unknown'})"
    base["summary"] = "Protocolo não reconhecido pelo parser manual"
    return base
# ...existing code...