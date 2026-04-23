"""
sniffer.py — Ponto de entrada do Packet Sniffer
Redes de Computadores, LEI - Universidade do Minho, 2025/2026

Uso direto:
  sudo python3 sniffer.py -i eth0
  sudo python3 sniffer.py -i eth0 --proto TCP --log captura.csv
  sudo python3 sniffer.py -i eth0 --bpf "udp port 53" --log dns.json

Interface interativa:
  sudo python3 menu.py
"""

import argparse
import signal
import sys

from scapy.sendrecv import sniff
from scapy.arch import get_if_list

from parser import parse_packet
from filters import PacketFilter, check_bpf_proto_conflict
from logger import PacketLogger


# =============================================================================
# ESTADO GLOBAL DA SESSÃO
# =============================================================================

_packet_count = 0
_filter: PacketFilter
_logger: PacketLogger | None = None
_live: bool = True
_iface: str = "?"


# =============================================================================
# FORMATAÇÃO PARA TERMINAL (modo live)
# =============================================================================

COLORS = {
    "ARP":     "\033[93m",
    "ICMP":    "\033[96m",
    "TCP":     "\033[92m",
    "UDP":     "\033[94m",
    "DNS":     "\033[95m",
    "DHCP":    "\033[91m",
    "HTTP":    "\033[32m",
    "IPV6":    "\033[36m",
    "DEFAULT": "\033[0m",
}
RESET  = "\033[0m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"


def _color_for(protocol: str) -> str:
    for key in COLORS:
        if key in protocol.upper():
            return COLORS[key]
    return COLORS["DEFAULT"]


def _print_packet(parsed: dict, pkt_num: int):
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
    hdr = (
        f"{'#':<6} {'Timestamp':23s}  {'Iface':8s}  "
        f"{'Protocol':20s}  {'Source':18s}    {'Destination':18s}  "
        f"{'Size':5s}  Summary"
    )
    print(BOLD + hdr + RESET)
    print("─" * 130)


# =============================================================================
# CALLBACK DE CAPTURA
# =============================================================================

def _packet_callback(pkt):
    global _packet_count, _filter, _logger, _live, _iface

    parsed = parse_packet(pkt, iface=_iface)
    if parsed is None:
        return

    if not _filter.match(parsed):
        return

    _packet_count += 1

    if _live:
        _print_packet(parsed, _packet_count)

    if _logger:
        _logger.log(parsed)


# =============================================================================
# SINAL DE INTERRUPÇÃO
# =============================================================================

def _handle_sigint(sig, frame):
    print(f"\n\n{BOLD}{'─'*50}")
    print(f"  Captura terminada.")
    print(f"  Total de pacotes capturados: {_packet_count}")
    if _logger:
        _logger.close()
        print(f"  Log guardado em: {_logger.filepath}")
    print(f"{'─'*50}{RESET}\n")
    sys.exit(0)


# =============================================================================
# FUNÇÃO PRINCIPAL (usada pelo menu.py e pela CLI)
# =============================================================================

def run_capture(iface, proto=None, ip=None, mac=None, bpf=None,
                log=None, live=True, count=0):
    """
    Ponto de entrada reutilizável — chamado pelo menu.py ou pela CLI.
    Retorna o número de pacotes capturados (se count > 0).
    """
    global _packet_count, _filter, _logger, _live, _iface

    _packet_count = 0
    _iface  = iface
    _live   = live
    _filter = PacketFilter(protocol=proto, ip=ip, mac=mac)
    _logger = None

    # --- Verificar conflito BPF + proto ---
    warning = check_bpf_proto_conflict(bpf or "", proto or "")
    if warning:
        print(f"\n{YELLOW}⚠  AVISO: {warning}{RESET}\n")
        resp = input("  Continuar mesmo assim? [s/N] ").strip().lower()
        if resp != "s":
            print("  Captura cancelada.")
            return 0

    if log:
        try:
            _logger = PacketLogger(log)
        except ValueError as e:
            print(f"{RED}Erro: {e}{RESET}")
            return 0

    signal.signal(signal.SIGINT, _handle_sigint)

    if live:
        _print_header()

    sniff(
        iface=iface,
        filter=bpf or "",
        prn=_packet_callback,
        count=count,
        store=False,
    )

    # Chegou aqui se count foi atingido
    if _logger:
        _logger.close()

    return _packet_count


# =============================================================================
# ARGPARSE — CLI direta
# =============================================================================

def _build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Packet Sniffer — RC TP2, LEI UMinho 2025/2026",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-i", "--iface", help="Interface de rede")
    parser.add_argument("--list", action="store_true", help="Lista interfaces disponíveis")
    parser.add_argument("--proto", metavar="PROTOCOLO")
    parser.add_argument("--ip",    metavar="ENDEREÇO")
    parser.add_argument("--mac",   metavar="ENDEREÇO")
    parser.add_argument("--bpf",   metavar="EXPRESSÃO")
    parser.add_argument("--log",   metavar="FICHEIRO")
    parser.add_argument("--no-live", action="store_true")
    parser.add_argument("--count", type=int, default=0, metavar="N")
    return parser


def main():
    arg_parser = _build_arg_parser()
    args = arg_parser.parse_args()

    if args.list:
        print("\nInterfaces de rede disponíveis:")
        for iface in get_if_list():
            print(f"  • {iface}")
        print()
        sys.exit(0)

    if not args.iface:
        arg_parser.error("Especifica uma interface com -i/--iface (ou usa --list).")

    live = not args.no_live
    if not live and not args.log:
        arg_parser.error("--no-live requer --log.")

    print(f"\n{BOLD}{'═'*60}")
    print(f"  Packet Sniffer — RC TP2 | LEI UMinho 2025/2026")
    print(f"{'═'*60}{RESET}")
    print(f"  Interface : {args.iface}")
    if args.bpf:   print(f"  Filtro BPF: {args.bpf}")
    if args.proto: print(f"  Protocolo : {args.proto}")
    if args.ip:    print(f"  IP        : {args.ip}")
    if args.mac:   print(f"  MAC       : {args.mac}")
    print(f"  Modo live : {'Ativo' if live else 'Inativo'}")
    print(f"  Log       : {args.log or 'Inativo'}")
    print(f"  Count     : {'∞' if args.count == 0 else args.count}")
    print(f"  Ctrl+C para parar.\n")

    run_capture(
        iface=args.iface,
        proto=args.proto,
        ip=args.ip,
        mac=args.mac,
        bpf=args.bpf,
        log=args.log,
        live=live,
        count=args.count,
    )


if __name__ == "__main__":
    main()