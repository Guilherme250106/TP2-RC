"""
menu.py — Interface interativa do Packet Sniffer
Redes de Computadores, LEI - Universidade do Minho, 2025/2026

Uso:
  sudo python3 menu.py
"""

import os
import sys

from scapy.arch import get_if_list
from sniffer import run_capture

# =============================================================================
# ANSI
# =============================================================================

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"

def clr():
    os.system("clear")

def _c(color, text):
    return f"{color}{text}{RESET}"

# =============================================================================
# PRESETS — cenários prontos a usar
# =============================================================================

PRESETS = [
    {
        "name":  "Ping / ICMP",
        "desc":  "Captura pedidos e respostas ICMP (echo request/reply)",
        "proto": "ICMP",
        "bpf":   "icmp",
        "tip":   "Corre `ping <ip>` noutro terminal para gerar tráfego.",
    },
    {
        "name":  "ARP",
        "desc":  "Captura ARP requests e replies na rede local",
        "proto": "ARP",
        "bpf":   "arp",
        "tip":   "Qualquer comunicação nova na LAN gera ARPs.",
    },
    {
        "name":  "DNS",
        "desc":  "Captura queries e respostas DNS (porta UDP 53)",
        "proto": "DNS",
        "bpf":   "udp port 53",
        "tip":   "Abre o browser ou corre `nslookup google.com`.",
    },
    {
        "name":  "HTTP",
        "desc":  "Captura tráfego HTTP (porta TCP 80)",
        "proto": "HTTP",
        "bpf":   "tcp port 80",
        "tip":   "Usa `curl http://example.com` (não https).",
    },
    {
        "name":  "DHCP",
        "desc":  "Captura mensagens DHCP Discover/Offer/Request/ACK",
        "proto": "DHCP",
        "bpf":   "udp port 67 or udp port 68",
        "tip":   "Desliga e volta a ligar o Wi-Fi para forçar um DHCP.",
    },
    {
        "name":  "TCP completo",
        "desc":  "Todo o tráfego TCP (handshake, dados, FIN)",
        "proto": "TCP",
        "bpf":   "tcp",
        "tip":   "Qualquer ligação TCP (browser, SSH, etc.) gera tráfego.",
    },
    {
        "name":  "UDP genérico",
        "desc":  "Todo o tráfego UDP",
        "proto": "UDP",
        "bpf":   "udp",
        "tip":   "",
    },
    {
        "name":  "Tudo (sem filtro)",
        "desc":  "Captura todos os pacotes — útil para explorar",
        "proto": None,
        "bpf":   None,
        "tip":   "Usa --count para limitar se a rede estiver movimentada.",
    },
]

# =============================================================================
# ESTADO DA SESSÃO
# =============================================================================

cfg = {
    "iface":  None,
    "proto":  None,
    "ip":     None,
    "mac":    None,
    "bpf":    None,
    "log":    None,
    "live":   True,
    "count":  0,
}


# =============================================================================
# DESENHO DO MENU
# =============================================================================

def _draw_header():
    print(_c(BOLD + CYAN, "╔══════════════════════════════════════════════╗"))
    print(_c(BOLD + CYAN, "║   Packet Sniffer — RC TP2  |  LEI UMinho    ║"))
    print(_c(BOLD + CYAN, "╚══════════════════════════════════════════════╝"))
    print()


def _val(v, fallback="—"):
    return _c(GREEN, str(v)) if v else _c(DIM, fallback)


def _draw_config():
    print(_c(BOLD, "  Configuração atual"))
    print(_c(DIM, "  " + "─"*44))
    print(f"  {'Interface':<12} {_val(cfg['iface'], 'não selecionada')}")
    print(f"  {'Protocolo':<12} {_val(cfg['proto'])}")
    print(f"  {'IP':<12} {_val(cfg['ip'])}")
    print(f"  {'MAC':<12} {_val(cfg['mac'])}")
    print(f"  {'BPF':<12} {_val(cfg['bpf'])}")
    print(f"  {'Log':<12} {_val(cfg['log'])}")
    print(f"  {'Modo live':<12} {_c(GREEN, 'Sim') if cfg['live'] else _c(DIM, 'Não')}")
    count_str = "∞" if cfg["count"] == 0 else str(cfg["count"])
    print(f"  {'Count':<12} {_c(GREEN, count_str)}")
    print()


def _draw_menu():
    print(_c(BOLD, "  Menu"))
    print(_c(DIM, "  " + "─"*44))
    print(f"  {_c(CYAN,  '1')}  Selecionar interface")
    print(f"  {_c(CYAN,  '2')}  Presets rápidos (protocolos)")
    print(f"  {_c(CYAN,  '3')}  Filtros manuais")
    print(f"  {_c(CYAN,  '4')}  Opções de log")
    print(f"  {_c(GREEN, '5')}  ▶  Iniciar captura")
    print(f"  {_c(RED,   '0')}  Sair")
    print()


# =============================================================================
# SUBMENUS
# =============================================================================

def menu_interface():
    clr()
    _draw_header()
    ifaces = get_if_list()
    print(_c(BOLD, "  Interfaces disponíveis\n"))
    for i, iface in enumerate(ifaces, 1):
        print(f"  {_c(CYAN, str(i))}  {iface}")
    print(f"\n  {_c(DIM, 'Enter = manter atual')} ({_val(cfg['iface'])})")
    print()
    choice = input("  Escolha: ").strip()
    if choice == "":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(ifaces):
            cfg["iface"] = ifaces[idx]
            print(_c(GREEN, f"\n  Interface selecionada: {cfg['iface']}"))
        else:
            print(_c(RED, "\n  Opção inválida."))
        input(_c(DIM, "  Enter para continuar..."))
    except ValueError:
        pass


def menu_presets():
    clr()
    _draw_header()
    print(_c(BOLD, "  Presets rápidos\n"))
    for i, p in enumerate(PRESETS, 1):
        print(f"  {_c(CYAN, str(i))}  {_c(BOLD, p['name']):<28} {_c(DIM, p['desc'])}")
    print(f"\n  {_c(DIM, 'Enter = não alterar')}\n")
    choice = input("  Escolha: ").strip()
    if choice == "":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(PRESETS):
            p = PRESETS[idx]
            cfg["proto"] = p["proto"]
            cfg["bpf"]   = p["bpf"]
            # Limpar filtros ip/mac ao mudar preset (fazem pouco sentido combinados)
            cfg["ip"]  = None
            cfg["mac"] = None
            print(_c(GREEN, f"\n  Preset aplicado: {p['name']}"))
            if p["tip"]:
                print(_c(YELLOW, f"  Dica: {p['tip']}"))
        else:
            print(_c(RED, "\n  Opção inválida."))
        input(_c(DIM, "\n  Enter para continuar..."))
    except ValueError:
        pass


def menu_filtros():
    while True:
        clr()
        _draw_header()
        print(_c(BOLD, "  Filtros manuais\n"))
        print(f"  {_c(CYAN, '1')}  Protocolo    {_val(cfg['proto'])}")
        print(f"  {_c(CYAN, '2')}  IP           {_val(cfg['ip'])}")
        print(f"  {_c(CYAN, '3')}  MAC          {_val(cfg['mac'])}")
        print(f"  {_c(CYAN, '4')}  BPF          {_val(cfg['bpf'])}")
        print(f"  {_c(CYAN, '5')}  Count        {_c(GREEN, '∞') if cfg['count']==0 else _c(GREEN, str(cfg['count']))}")
        print(f"\n  {_c(CYAN, 'L')}  Limpar todos os filtros")
        print(f"  {_c(DIM,  '0')}  Voltar\n")
        choice = input("  Opção: ").strip().lower()

        if choice == "0":
            break

        elif choice == "1":
            print(_c(DIM, "  Protocolos: ARP, ICMP, ICMPv6, TCP, UDP, DNS, DHCP, HTTP"))
            v = input("  Protocolo (Enter=limpar): ").strip().upper()
            cfg["proto"] = v if v else None

        elif choice == "2":
            v = input("  IP (Enter=limpar): ").strip()
            cfg["ip"] = v if v else None

        elif choice == "3":
            v = input("  MAC (Enter=limpar): ").strip()
            cfg["mac"] = v if v else None

        elif choice == "4":
            print(_c(DIM, '  Exemplos: "tcp port 80"  |  "udp port 53"  |  "host 1.2.3.4"'))
            v = input("  BPF (Enter=limpar): ").strip()
            cfg["bpf"] = v if v else None

        elif choice == "5":
            v = input("  Nº de pacotes (0=infinito): ").strip()
            try:
                cfg["count"] = max(0, int(v))
            except ValueError:
                print(_c(RED, "  Valor inválido."))
                input(_c(DIM, "  Enter para continuar..."))

        elif choice == "l":
            cfg["proto"] = cfg["ip"] = cfg["mac"] = cfg["bpf"] = None
            cfg["count"] = 0
            print(_c(GREEN, "\n  Filtros limpos."))
            input(_c(DIM, "  Enter para continuar..."))


def menu_log():
    while True:
        clr()
        _draw_header()
        print(_c(BOLD, "  Opções de log\n"))
        print(f"  {_c(CYAN, '1')}  Ficheiro de log   {_val(cfg['log'])}")
        live_str = _c(GREEN, "Ativo") if cfg["live"] else _c(DIM, "Inativo")
        print(f"  {_c(CYAN, '2')}  Modo live         {live_str}")
        print(f"\n  {_c(DIM, '0')}  Voltar\n")
        choice = input("  Opção: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            print(_c(DIM, "  Formatos suportados: .txt  .csv  .json"))
            v = input("  Nome do ficheiro (Enter=sem log): ").strip()
            if v and not any(v.endswith(ext) for ext in [".txt", ".csv", ".json"]):
                print(_c(RED, "  Extensão inválida. Usa .txt, .csv ou .json."))
                input(_c(DIM, "  Enter para continuar..."))
            else:
                cfg["log"] = v if v else None

        elif choice == "2":
            cfg["live"] = not cfg["live"]
            if not cfg["live"] and not cfg["log"]:
                print(_c(YELLOW, "\n  Aviso: sem log ativo, a captura não produz output."))
                cfg["live"] = True
                input(_c(DIM, "  Define primeiro um ficheiro de log. Enter para continuar..."))


def iniciar_captura():
    clr()
    _draw_header()

    if not cfg["iface"]:
        print(_c(RED, "  Erro: seleciona uma interface primeiro (opção 1).\n"))
        input(_c(DIM, "  Enter para voltar..."))
        return

    print(_c(BOLD, "  Resumo da captura\n"))
    print(f"  Interface : {_c(GREEN, cfg['iface'])}")
    if cfg["proto"]: print(f"  Protocolo : {_c(GREEN, cfg['proto'])}")
    if cfg["bpf"]:   print(f"  BPF       : {_c(GREEN, cfg['bpf'])}")
    if cfg["ip"]:    print(f"  IP        : {_c(GREEN, cfg['ip'])}")
    if cfg["mac"]:   print(f"  MAC       : {_c(GREEN, cfg['mac'])}")
    if cfg["log"]:   print(f"  Log       : {_c(GREEN, cfg['log'])}")
    count_str = "∞" if cfg["count"] == 0 else str(cfg["count"])
    print(f"  Count     : {_c(GREEN, count_str)}")
    print()

    # Mostrar dica do preset ativo (se aplicável)
    for p in PRESETS:
        if p["proto"] == cfg["proto"] and p["bpf"] == cfg["bpf"] and p["tip"]:
            print(_c(YELLOW, f"  Dica: {p['tip']}"))
            print()
            break

    print(_c(DIM, "  Ctrl+C para parar a captura.\n"))
    print(_c(DIM, "─" * 130))
    print()

    run_capture(
        iface  = cfg["iface"],
        proto  = cfg["proto"],
        ip     = cfg["ip"],
        mac    = cfg["mac"],
        bpf    = cfg["bpf"],
        log    = cfg["log"],
        live   = cfg["live"],
        count  = cfg["count"],
    )

    print()
    input(_c(DIM, "  Enter para voltar ao menu..."))


# =============================================================================
# LOOP PRINCIPAL
# =============================================================================

def main():
    # Verificar root
    if os.geteuid() != 0:
        print(_c(RED + BOLD, "\n  Erro: este programa precisa de ser executado como root."))
        print(_c(DIM,        "  Usa: sudo python3 menu.py\n"))
        sys.exit(1)

    # Tentar pré-selecionar uma interface óbvia
    ifaces = get_if_list()
    for candidate in ("eth0", "ens3", "wlan0", "wlp2s0", "enp0s3"):
        if candidate in ifaces:
            cfg["iface"] = candidate
            break

    while True:
        clr()
        _draw_header()
        _draw_config()
        _draw_menu()

        choice = input("  Opção: ").strip()

        if choice == "1":
            menu_interface()
        elif choice == "2":
            menu_presets()
        elif choice == "3":
            menu_filtros()
        elif choice == "4":
            menu_log()
        elif choice == "5":
            iniciar_captura()
        elif choice == "0":
            clr()
            print(_c(DIM, "\n  Sniffer encerrado.\n"))
            sys.exit(0)


if __name__ == "__main__":
    main()