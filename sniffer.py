"""
sniffer.py — Ponto de entrada do Packet Sniffer
Redes de Computadores, LEI - Universidade do Minho, 2025/2026

Uso:
  sudo python3 sniffer.py -i eth0
  sudo python3 sniffer.py -i eth0 --proto TCP --log captura.csv
  sudo python3 sniffer.py -i eth0 --ip 192.168.1.1 --log out.json --count 50
  sudo python3 sniffer.py -i eth0 --bpf "tcp port 80"
  sudo python3 sniffer.py --list
"""

import argparse
import signal
import sys

from scapy.sendrecv import sniff
from scapy.arch import get_if_list
from scapy.config import conf

from parser import parse_packet
from filters import PacketFilter
from logger import PacketLogger


# =============================================================================
# ESTADO GLOBAL DA SESSÃO
# =============================================================================

_packet_count  = 0       # Número total de pacotes capturados nesta sessão
_filter: PacketFilter    # Filtro ativo
_logger: PacketLogger | None = None   # Logger (None se modo log não estiver ativo)
_live: bool = True       # Se True, imprime no terminal


# =============================================================================
# FORMATAÇÃO PARA TERMINAL (modo live)
# =============================================================================

# Cores ANSI para distinguir protocolos visualmente no terminal
COLORS = {
    "ARP":   "\033[93m",   # Amarelo
    "ICMP":  "\033[96m",   # Ciano
    "TCP":   "\033[92m",   # Verde
    "UDP":   "\033[94m",   # Azul
    "DNS":   "\033[95m",   # Magenta
    "DHCP":  "\033[91m",   # Vermelho
    "HTTP":  "\033[32m",   # Verde escuro
    "IPv6":  "\033[36m",   # Ciano escuro
    "DEFAULT": "\033[0m",  # Reset
}
RESET = "\033[0m"


def _color_for(protocol: str) -> str:
    """Devolve o código de cor ANSI para um dado protocolo."""
    for key in COLORS:
        if key in protocol.upper():
            return COLORS[key]
    return COLORS["DEFAULT"]


def _print_packet(parsed: dict, pkt_num: int):
    """
    Imprime uma linha formatada no terminal para um pacote.
    Formato: #N  [timestamp]  IFACE  PROTO  src->dst  SIZE  SUMMARY
    """
    color = _color_for(parsed["protocol"])
    proto = parsed["protocol"][:20].ljust(20)
    src   = (parsed["src_ip"] or parsed["src_mac"] or "?")[:18].ljust(18)
    dst   = (parsed["dst_ip"] or parsed["dst_mac"] or "?")[:18].ljust(18)

    print(
        f"{color}"
        f"#{pkt_num:<5d} "
        f"[{parsed['timestamp']}]  "
        f"{parsed['interface']:8s}  "
        f"{proto}  "
        f"{src} -> {dst}  "
        f"{parsed['size']:5d}B  "
        f"{parsed['summary']}"
        f"{RESET}"
    )


def _print_header():
    """Imprime o cabeçalho da tabela no terminal."""
    hdr = (
        f"{'#':<6} {'Timestamp':23s}  {'Iface':8s}  "
        f"{'Protocol':20s}  {'Source':18s}    {'Destination':18s}  "
        f"{'Size':5s}  Summary"
    )
    print("\033[1m" + hdr + RESET)
    print("─" * 130)


# =============================================================================
# CALLBACK DE CAPTURA
# =============================================================================

def _packet_callback(pkt):
    """
    Chamado pelo Scapy para cada pacote capturado na interface.
    1. Faz o parsing do pacote.
    2. Aplica os filtros.
    3. Se passou: exibe no terminal e/ou guarda em ficheiro.
    """
    global _packet_count, _filter, _logger, _live

    parsed = parse_packet(pkt, iface=conf.iface)
    if parsed is None:
        return  # Pacote sem Ethernet — ignorar

    # Aplicar filtros
    if not _filter.match(parsed):
        return

    _packet_count += 1

    # Modo live — imprimir no terminal
    if _live:
        _print_packet(parsed, _packet_count)

    # Modo log — guardar em ficheiro
    if _logger:
        _logger.log(parsed)


# =============================================================================
# SINAL DE INTERRUPÇÃO (Ctrl+C)
# =============================================================================

def _handle_sigint(sig, frame):
    """Trata Ctrl+C graciosamente: fecha o logger e imprime estatísticas."""
    print(f"\n\n\033[1m{'─'*50}")
    print(f"  Captura terminada.")
    print(f"  Total de pacotes capturados: {_packet_count}")
    if _logger:
        _logger.close()
        print(f"  Log guardado em: {_logger.filepath}")
    print(f"{'─'*50}\033[0m\n")
    sys.exit(0)


# =============================================================================
# ARGPARSE — INTERFACE DE LINHA DE COMANDOS
# =============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Packet Sniffer — RC TP2, LEI UMinho 2025/2026",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 sniffer.py --list
  sudo python3 sniffer.py -i eth0
  sudo python3 sniffer.py -i eth0 --proto TCP
  sudo python3 sniffer.py -i eth0 --ip 192.168.1.1 --log cap.csv
  sudo python3 sniffer.py -i eth0 --bpf "udp port 53" --log dns.json
  sudo python3 sniffer.py -i eth0 --count 100 --no-live --log output.txt
        """
    )

    parser.add_argument(
        "-i", "--iface",
        help="Interface de rede a escutar (ex: eth0, wlan0, lo).\n"
             "Use --list para ver interfaces disponíveis."
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Lista as interfaces de rede disponíveis e termina."
    )
    parser.add_argument(
        "--proto",
        metavar="PROTOCOLO",
        help="Filtrar por protocolo (ex: TCP, UDP, ARP, ICMP, DNS, DHCP, HTTP)."
    )
    parser.add_argument(
        "--ip",
        metavar="ENDEREÇO",
        help="Filtrar por endereço IP (origem ou destino)."
    )
    parser.add_argument(
        "--mac",
        metavar="ENDEREÇO",
        help="Filtrar por endereço MAC (origem ou destino)."
    )
    parser.add_argument(
        "--bpf",
        metavar="EXPRESSÃO",
        help="Filtro BPF (Berkeley Packet Filter), ex: \"tcp port 80\".\n"
             "Aplicado ao nível do driver — mais eficiente para grandes volumes."
    )
    parser.add_argument(
        "--log",
        metavar="FICHEIRO",
        help="Guardar captura em ficheiro. Extensão determina formato:\n"
             "  .txt  — texto legível\n"
             "  .csv  — tabela CSV\n"
             "  .json — array JSON"
    )
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="Desativar impressão no terminal (só log em ficheiro)."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        metavar="N",
        help="Parar após capturar N pacotes (0 = infinito)."
    )

    return parser


# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

def main():
    global _filter, _logger, _live

    arg_parser = _build_arg_parser()
    args = arg_parser.parse_args()

    # --- Listar interfaces ---
    if args.list:
        print("\nInterfaces de rede disponíveis:")
        for iface in get_if_list():
            print(f"  • {iface}")
        print()
        sys.exit(0)

    # --- Validar interface ---
    if not args.iface:
        arg_parser.error("É obrigatório especificar uma interface com -i/--iface "
                         "(ou usar --list para ver as disponíveis).")

    # --- Configurar interface no Scapy ---
    conf.iface = args.iface

    # --- Configurar filtros ---
    _filter = PacketFilter(
        protocol=args.proto,
        ip=args.ip,
        mac=args.mac,
    )

    # --- Configurar logger ---
    _live = not args.no_live
    if args.log:
        try:
            _logger = PacketLogger(args.log)
        except ValueError as e:
            arg_parser.error(str(e))

    # --- Validar que pelo menos um output está ativo ---
    if not _live and not _logger:
        arg_parser.error("--no-live requer --log. Sem output, a captura não serviria de nada.")

    # --- Registar handler para Ctrl+C ---
    signal.signal(signal.SIGINT, _handle_sigint)

    # --- Banner de início ---
    print(f"\n\033[1m{'═'*60}")
    print(f"  Packet Sniffer — RC TP2 | LEI UMinho 2025/2026")
    print(f"{'═'*60}\033[0m")
    print(f"  Interface : {args.iface}")
    print(f"  {_filter}")
    if args.bpf:
        print(f"  Filtro BPF: {args.bpf}")
    print(f"  Modo live : {'Ativo' if _live else 'Inativo'}")
    print(f"  Log       : {args.log if args.log else 'Inativo'}")
    print(f"  Count     : {'∞' if args.count == 0 else args.count} pacotes")
    print(f"  Ctrl+C para parar.\n")

    if _live:
        _print_header()

    # --- Iniciar captura com Scapy ---
    sniff(
        iface=args.iface,
        filter=args.bpf or "",        # Filtro BPF (nível kernel)
        prn=_packet_callback,          # Callback por pacote
        count=args.count,              # 0 = captura infinita
        store=False,                   # Não acumular em memória
    )

    # Se chegou aqui, o count foi atingido (não foi Ctrl+C)
    _handle_sigint(None, None)


if __name__ == "__main__":
    main()
