"""
filters.py — Módulo de filtros do Packet Sniffer
"""

# Mapeamento entre nomes de protocolo e expressões BPF equivalentes.
# Usado para detetar conflitos entre --bpf e --proto.
_PROTO_TO_BPF_KEYWORD = {
    "TCP":   "tcp",
    "UDP":   "udp",
    "ICMP":  "icmp",
    "ARP":   "arp",
    "DNS":   "udp",   # DNS corre sobre UDP
    "DHCP":  "udp",   # DHCP corre sobre UDP
    "HTTP":  "tcp",   # HTTP corre sobre TCP
    "IPV6":  "ip6",
    "ICMPV6":"icmp6",
}


def check_bpf_proto_conflict(bpf: str, protocol: str) -> str | None:
    """
    Verifica se o filtro BPF e o filtro de protocolo python são contraditórios.
    Devolve uma mensagem de aviso se houver conflito, ou None se estiver tudo bem.

    Exemplos de conflito:
      --bpf "tcp" --proto UDP   →  BPF só deixa passar TCP, mas o filtro python
                                    só aceita UDP → zero pacotes garantido.
      --bpf "udp port 53" --proto TCP → idem.
    """
    if not bpf or not protocol:
        return None

    bpf_lower    = bpf.lower()
    proto_upper  = protocol.upper()

    # Protocolo que o BPF deixa passar (inferido da expressão)
    bpf_allows_tcp  = "tcp"  in bpf_lower
    bpf_allows_udp  = "udp"  in bpf_lower
    bpf_allows_icmp = "icmp" in bpf_lower
    bpf_allows_arp  = "arp"  in bpf_lower
    bpf_is_specific = any([bpf_allows_tcp, bpf_allows_udp,
                            bpf_allows_icmp, bpf_allows_arp])

    if not bpf_is_specific:
        return None   # BPF genérico (ex: "host 1.2.3.4") — sem conflito detetável

    needed_bpf = _PROTO_TO_BPF_KEYWORD.get(proto_upper)
    if needed_bpf is None:
        return None   # Protocolo não mapeado, não conseguimos verificar

    # Conflito: o BPF restringe a um tipo de tráfego, mas o proto python pede outro
    if needed_bpf == "tcp"  and not bpf_allows_tcp:
        return (f"Conflito de filtros: --bpf '{bpf}' não deixa passar tráfego TCP, "
                f"mas --proto {protocol} requer TCP. Nenhum pacote será capturado.")
    if needed_bpf == "udp"  and not bpf_allows_udp:
        return (f"Conflito de filtros: --bpf '{bpf}' não deixa passar tráfego UDP, "
                f"mas --proto {protocol} (que usa UDP) nunca será visto. "
                f"Nenhum pacote será capturado.")
    if needed_bpf == "icmp" and not bpf_allows_icmp:
        return (f"Conflito de filtros: --bpf '{bpf}' não deixa passar ICMP, "
                f"mas --proto {protocol} requer ICMP. Nenhum pacote será capturado.")
    if needed_bpf == "arp"  and not bpf_allows_arp:
        return (f"Conflito de filtros: --bpf '{bpf}' não deixa passar ARP, "
                f"mas --proto {protocol} requer ARP. Nenhum pacote será capturado.")

    return None


class PacketFilter:
    """
    Encapsula todos os critérios de filtragem configurados pelo utilizador.
    Os filtros são aplicados em conjunto (AND lógico).
    """

    def __init__(self, protocol=None, ip=None, mac=None):
        self.protocol = protocol.upper() if protocol else None
        self.ip       = ip.strip()       if ip       else None
        self.mac      = mac.lower()      if mac      else None

    def match(self, parsed: dict) -> bool:
        if self.protocol is not None:
            pkt_proto = parsed.get("protocol", "").upper()
            if self.protocol not in pkt_proto:
                return False

        if self.ip is not None:
            src_ip = parsed.get("src_ip", "")
            dst_ip = parsed.get("dst_ip", "")
            if self.ip != src_ip and self.ip != dst_ip:
                return False

        if self.mac is not None:
            src_mac = parsed.get("src_mac", "").lower()
            dst_mac = parsed.get("dst_mac", "").lower()
            if self.mac != src_mac and self.mac != dst_mac:
                return False

        return True

    def is_active(self) -> bool:
        return any([self.protocol, self.ip, self.mac])

    def __str__(self):
        parts = []
        if self.protocol: parts.append(f"protocolo={self.protocol}")
        if self.ip:       parts.append(f"ip={self.ip}")
        if self.mac:      parts.append(f"mac={self.mac}")
        return "Filtros: [" + ", ".join(parts) + "]" if parts else "Sem filtros ativos"