
"""
sniffer.py — Ponto de entrada do Packet Sniffer
Mantém a lógica atual (callback robusto, parsers manuais, PacketLogger) mas
restaura a interface de terminal antiga (header, colunas, cores, filtros).
Uso CLI (ex.: sudo python3 sniffer.py -i wlp2s0) ou via menu.py (run_capture).
"""
import argparse
import signal
import sys
import time
from datetime import datetime

from scapy.sendrecv import sniff
from scapy.arch import get_if_list

from parser import parse_packet
from filters import PacketFilter, check_bpf_proto_conflict

# tentar importar PacketLogger (logger.py)
try:
    from logger import PacketLogger
except Exception:
    PacketLogger = None

# =============================================================================
# ESTADO GLOBAL DA SESSÃO
# =============================================================================
_packet_count = 0
_filter: PacketFilter
_logger: PacketLogger | None = None
_log_fp = None  # fallback plain file handle if PacketLogger não disponível
_live: bool = True
_iface: str = "?"

# controlo de repetição de erros
_last_error_msg = None
_last_error_time = 0.0
_ERROR_SUPPRESSION_WINDOW = 2.0  # segundos

# =============================================================================
# FORMATAÇÃO PARA TERMINAL (modo live) — como na interface antiga
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
    if not protocol:
        return COLORS["DEFAULT"]
    up = protocol.upper()
    for key in COLORS:
        if key in up:
            return COLORS[key]
    return COLORS["DEFAULT"]


def _print_header():
    hdr = (
        f"{'#':<6} {'Timestamp':23s}  {'Iface':8s}  "
        f"{'Protocol':20s}  {'Source':18s}    {'Destination':18s}  "
        f"{'Size':5s}  Summary"
    )
    print(BOLD + hdr + RESET)
    print("─" * 130)


def _print_packet(parsed: dict, pkt_num: int):
    color = _color_for(parsed.get("protocol", ""))
    proto = (parsed.get("protocol") or "")[:20].ljust(20)
    src   = (parsed.get("src_ip") or parsed.get("src_mac") or "?")[:18].ljust(18)
    dst   = (parsed.get("dst_ip") or parsed.get("dst_mac") or "?")[:18].ljust(18)
    print(
        f"{color}"
        f"#{pkt_num:<5d} "
        f"[{parsed.get('timestamp')}]  "
        f"{parsed.get('interface', ''):8s}  "
        f"{proto}  "
        f"{src} -> {dst}  "
        f"{parsed.get('size',0):5d}B  "
        f"{parsed.get('summary','')}"
        f"{RESET}"
    )


# =============================================================================
# CALLBACK DE CAPTURA (robusto contra exceções)
# =============================================================================
def _packet_callback(pkt):
    global _packet_count, _filter, _logger, _log_fp, _live, _iface, _last_error_msg, _last_error_time
    try:
        parsed = parse_packet(pkt, iface=_iface)
        if parsed is None:
            return

        # filtro de aplicação do user
        try:
            if not _filter.match(parsed):
                return
        except Exception:
            # se o filtro falhar, não interromper a captura
            return

        _packet_count += 1

        if _live:
            _print_packet(parsed, _packet_count)

        # Logging: PacketLogger preferido, fallback a file handle (JSON por linha)
        if _logger is not None:
            try:
                _logger.log(parsed)
            except Exception:
                pass
        elif _log_fp is not None:
            try:
                import json as _json
                _log_fp.write(_json.dumps(parsed, ensure_ascii=False) + "\n")
                _log_fp.flush()
            except Exception:
                pass

    except Exception as e:
        # suprimir flood de mensagens idênticas
        msg = str(e)
        now = time.time()
        if msg != _last_error_msg or (now - _last_error_time) > _ERROR_SUPPRESSION_WINDOW:
            print(f"Packet handler error: {msg}", file=sys.stderr)
            _last_error_msg = msg
            _last_error_time = now
        return


# =============================================================================
# SINAL DE INTERRUPÇÃO
# =============================================================================
def _handle_sigint(sig, frame):
    global _logger, _log_fp, _packet_count
    print(f"\n\n{BOLD}{'─'*50}")
    print(f"  Captura terminada.")
    print(f"  Total de pacotes capturados: {_packet_count}")
    try:
        if _logger:
            _logger.close()
            print(f"  Log guardado em: {_logger.filepath}")
        elif _log_fp:
            _log_fp.close()
            print(f"  Log guardado em: {_log_fp.name}")
    except Exception:
        pass
    print(f"{'─'*50}{RESET}\n")
    sys.exit(0)


# =============================================================================
# FUNÇÃO PRINCIPAL (usada pelo menu.py e pela CLI)
# =============================================================================
def run_capture(iface, proto=None, ip=None, mac=None, bpf=None,
                log=None, live=True, count=0, **kwargs):
    """
    Ponto de entrada reutilizável — chamado pelo menu.py ou pela CLI.
    Mantém assinatura compatível com menu.py (aceita 'log' e outros kwargs).
    """
    global _packet_count, _filter, _logger, _log_fp, _live, _iface

    _packet_count = 0
    _iface = iface
    _live = live
    _filter = PacketFilter(protocol=proto, ip=ip, mac=mac)
    _logger = None
    _log_fp = None

    # --- Verificar conflito BPF + proto ---
    warning = check_bpf_proto_conflict(bpf or "", proto or "")
    if warning:
        print(f"\n{YELLOW}⚠  AVISO: {warning}{RESET}\n")
        try:
            resp = input("  Continuar mesmo assim? [s/N] ").strip().lower()
        except Exception:
            resp = "n"
        if resp != "s":
            print("  Captura cancelada.")
            return 0

    # abrir logger se solicitado (menu passa 'log' como arg)
    if log:
        try:
            if PacketLogger is not None:
                _logger = PacketLogger(log)
                print(f"Log aberto (PacketLogger) em {log}")
            else:
                _log_fp = open(log, "a", encoding="utf-8")
                print(f"Log aberto em {log}")
        except ValueError as e:
            print(f"{RED}Erro: {e}{RESET}")
            return 0
        except Exception as e:
            print(f"{RED}Erro ao abrir log: {e}{RESET}")
            return 0

    # instalar handler SIGINT
    signal.signal(signal.SIGINT, _handle_sigint)

    if _live:
        _print_header()

    try:
        sniff(
            iface=iface,
            filter=bpf or "",
            prn=_packet_callback,
            count=count,
            store=False,
        )
    except Exception as e:
        print(f"Erro na captura: {e}", file=sys.stderr)

    # fechar logger se count terminou
    try:
        if _logger:
            _logger.close()
        elif _log_fp:
            _log_fp.close()
    except Exception:
        pass

    return _packet_count


# =============================================================================
# ARGPARSE — CLI direta (mantém interface antiga)
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