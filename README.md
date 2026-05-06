# Packet Sniffer — RC TP2
**Redes de Computadores, LEI — Universidade do Minho, 2025/2026**

---

## Instalação

> Requer Python 3.10+. Verificar com `python3 --version`.

**1. Criar e ativar o ambiente virtual**

```bash
cd /caminho/para/o/projeto
python3 -m venv sniffer-env
source sniffer-env/bin/activate
```

**2. Verificar que o ambiente está ativo** (o prompt passa a começar com `(sniffer-env)`)

```bash
which python3
```

**3. Instalar dependências**

```bash
pip install --upgrade pip
pip install scapy
```

**4. Verificar instalação**

```bash
python3 -c "import scapy; print('Scapy OK')"
```

**5. Executar**

```bash
sudo -E sniffer-env/bin/python menu.py
```

---

## Estrutura do Projeto

```
sniffer/
├── menu.py           — Interface interativa no terminal (recomendado)
├── sniffer.py        — Ponto de entrada CLI + função run_capture() reutilizável
├── parser.py         — Orquestrador do parsing — coordena a cadeia de parsers manuais
├── parse_ethernet.py — Parser manual da camada Ethernet (camada 2)
├── parse_arp.py      — Parser manual do protocolo ARP
├── parse_ipv4.py     — Parser manual do cabeçalho IPv4
├── parse_ipv6.py     — Parser manual do cabeçalho IPv6
├── parse_icmp.py     — Parser manual do protocolo ICMP
├── parse_tcp.py      — Parser manual do protocolo TCP e HTTP
├── parse_udp.py      — Parser manual do protocolo UDP
├── parse_dns.py      — Parser manual do protocolo DNS
├── parse_dhcp.py     — Parser manual do protocolo DHCP/BOOTP
├── filters.py        — Filtragem de pacotes + deteção de conflitos BPF/proto
├── logger.py         — Logging para ficheiro (.txt/.csv/.json)
└── README.md         — Este ficheiro
```

---

## Protocolos Suportados

| Camada          | Protocolos                        |
|-----------------|-----------------------------------|
| 2 (Ligação)     | Ethernet, ARP                     |
| 3 (Rede)        | IPv4, IPv6, ICMP, ICMPv6          |
| 4 (Transporte)  | TCP, UDP                          |
| 7 (Aplicação)   | DNS, HTTP, DHCP                   |

---

## Como Executar

Há duas formas de usar o sniffer: a **interface interativa** (recomendada para testar funcionalidades) e a **CLI direta** (útil para scripts e automação).

---

### Interface interativa (menu.py)

```bash
sudo python3 menu.py
```

O menu apresenta a configuração atual e quatro opções antes de iniciar a captura:

```
  1  Selecionar interface
  2  Presets rápidos (protocolos)
  3  Filtros manuais
  4  Opções de log
  5  ▶  Iniciar captura
  0  Sair
```

**Fluxo típico para testar um protocolo:**

1. `1` → selecionar a interface (`eth0`, `wlan0`, etc.)
2. `2` → escolher o preset do protocolo a testar (aplica proto + BPF automaticamente)
3. `5` → iniciar captura — é mostrada uma dica do que correr noutro terminal para gerar tráfego
4. `Ctrl+C` → parar e ver estatísticas; o menu volta ao estado inicial

**Presets disponíveis:**

| Preset         | Protocolo | Filtro BPF                    | Como gerar tráfego                     |
|----------------|-----------|-------------------------------|----------------------------------------|
| Ping / ICMP    | ICMP      | `icmp`                        | `ping <ip>`                            |
| ARP            | ARP       | `arp`                         | Qualquer comunicação nova na LAN       |
| DNS            | DNS       | `udp port 53`                 | `nslookup google.com` ou abrir browser |
| HTTP           | HTTP      | `tcp port 80`                 | `curl http://example.com`              |
| DHCP           | DHCP      | `udp port 67 or udp port 68`  | Desligar e ligar a interface de rede   |
| TCP completo   | TCP       | `tcp`                         | Qualquer ligação TCP                   |
| UDP genérico   | UDP       | `udp`                         | DNS, DHCP, qualquer tráfego UDP        |
| Tudo           | —         | —                             | Qualquer tráfego                       |

Para filtros adicionais (IP, MAC, BPF personalizado, log, count) usa a opção `3` ou `4` antes de iniciar.

---

### CLI direta (sniffer.py)

#### Listar interfaces disponíveis

```bash
python3 sniffer.py --list
```

#### Captura simples (modo live)

```bash
sudo python3 sniffer.py -i eth0
```

#### Filtrar por protocolo

```bash
sudo python3 sniffer.py -i eth0 --proto TCP
sudo python3 sniffer.py -i eth0 --proto DNS
sudo python3 sniffer.py -i eth0 --proto ARP
```

#### Filtrar por IP ou MAC

```bash
sudo python3 sniffer.py -i eth0 --ip 192.168.1.1
sudo python3 sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```

#### Filtro BPF (Berkeley Packet Filter)

```bash
sudo python3 sniffer.py -i eth0 --bpf "tcp port 80"
sudo python3 sniffer.py -i eth0 --bpf "udp port 53"
sudo python3 sniffer.py -i eth0 --bpf "host 192.168.1.1"
```

> Se o filtro BPF e o `--proto` forem contraditórios (ex: `--bpf "tcp" --proto UDP`), o sniffer avisa antes de iniciar e pede confirmação.

#### Guardar log em ficheiro

```bash
sudo python3 sniffer.py -i eth0 --log captura.txt
sudo python3 sniffer.py -i eth0 --log captura.csv
sudo python3 sniffer.py -i eth0 --log captura.json
```

#### Modo log apenas (sem impressão no terminal)

```bash
sudo python3 sniffer.py -i eth0 --no-live --log captura.csv
```

#### Limitar número de pacotes

```bash
sudo python3 sniffer.py -i eth0 --count 100
```

#### Exemplos combinados

```bash
# 50 pacotes TCP, guardar em CSV e mostrar no terminal
sudo python3 sniffer.py -i eth0 --proto TCP --count 50 --log tcp_cap.csv

# Tráfego DNS de um IP específico, guardar em JSON
sudo python3 sniffer.py -i wlan0 --ip 8.8.8.8 --log dns_google.json

# BPF + log silencioso
sudo python3 sniffer.py -i eth0 --bpf "udp port 53" --no-live --log dns.json
```

---

## Parâmetros disponíveis (CLI)

| Parâmetro        | Descrição                                           |
|------------------|-----------------------------------------------------|
| `-i`, `--iface`  | Interface de rede (obrigatório)                     |
| `--list`         | Lista interfaces disponíveis                        |
| `--proto PROTO`  | Filtrar por protocolo                               |
| `--ip IP`        | Filtrar por endereço IP (origem ou destino)         |
| `--mac MAC`      | Filtrar por endereço MAC (origem ou destino)        |
| `--bpf EXPR`     | Expressão BPF (aplicada ao nível do kernel)         |
| `--log FICHEIRO` | Guardar em ficheiro (.txt / .csv / .json)           |
| `--no-live`      | Não imprimir no terminal (requer `--log`)           |
| `--count N`      | Parar após N pacotes (0 = infinito)                 |

---

## Executar no CORE

1. Abrir o CORE e criar a topologia desejada.
2. Fazer duplo clique num nó para abrir o terminal.
3. Navegar para a pasta do sniffer e executar:

```bash
cd /path/to/sniffer
python3 sniffer.py -i eth0
```

> No CORE, os nós correm como root — não é necessário `sudo` nem virtualenv.
> Para usar o menu interativo no CORE, o processo é o mesmo:

```bash
python3 menu.py
```

---

## Parar a captura

`Ctrl+C` termina a captura, exibe o total de pacotes capturados e fecha o ficheiro de log corretamente.