"""
filters.py — Módulo de filtros do Packet Sniffer
Responsável por aplicar filtros aos pacotes capturados antes de os processar/exibir.
"""

class PacketFilter:
    """
    Encapsula todos os critérios de filtragem configurados pelo utilizador.
    Os filtros são aplicados em conjunto (AND lógico): um pacote só passa se
    satisfizer TODOS os filtros ativos.
    """

    def __init__(self, protocol=None, ip=None, mac=None):
        """
        Args:
            protocol (str|None): Nome do protocolo a filtrar, ex: "TCP", "ARP".
                                  None significa sem filtro de protocolo.
            ip (str|None):       Endereço IP (origem OU destino) a filtrar.
                                  None significa sem filtro de IP.
            mac (str|None):      Endereço MAC (origem OU destino) a filtrar.
                                  None significa sem filtro de MAC.
        """
        # Normalizar para maiúsculas/minúsculas consistentes
        self.protocol = protocol.upper() if protocol else None
        self.ip       = ip.strip()  if ip  else None
        self.mac      = mac.lower() if mac else None

    def match(self, parsed: dict) -> bool:
        """
        Verifica se um pacote (já parseado) passa em todos os filtros ativos.

        Args:
            parsed (dict): Dicionário devolvido por parser.parse_packet(), com
                           campos como 'protocol', 'src_ip', 'dst_ip',
                           'src_mac', 'dst_mac'.

        Returns:
            bool: True se o pacote deve ser processado, False se deve ser ignorado.
        """

        # --- Filtro por protocolo ---
        if self.protocol is not None:
            # O campo 'protocol' pode ser uma string composta, ex: "TCP/HTTP"
            # Verificamos se o protocolo desejado aparece em algum lugar
            pkt_proto = parsed.get("protocol", "").upper()
            if self.protocol not in pkt_proto:
                return False

        # --- Filtro por IP ---
        if self.ip is not None:
            src_ip = parsed.get("src_ip", "")
            dst_ip = parsed.get("dst_ip", "")
            if self.ip != src_ip and self.ip != dst_ip:
                return False

        # --- Filtro por MAC ---
        if self.mac is not None:
            src_mac = parsed.get("src_mac", "").lower()
            dst_mac = parsed.get("dst_mac", "").lower()
            if self.mac != src_mac and self.mac != dst_mac:
                return False

        return True

    def is_active(self) -> bool:
        """Devolve True se pelo menos um filtro está configurado."""
        return any([self.protocol, self.ip, self.mac])

    def __str__(self):
        parts = []
        if self.protocol:
            parts.append(f"protocolo={self.protocol}")
        if self.ip:
            parts.append(f"ip={self.ip}")
        if self.mac:
            parts.append(f"mac={self.mac}")
        return "Filtros: [" + ", ".join(parts) + "]" if parts else "Sem filtros ativos"
