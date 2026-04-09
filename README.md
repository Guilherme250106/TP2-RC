# Packet Sniffer — RC TP2
**Redes de Computadores, LEI — Universidade do Minho, 2025/2026**

---

## Dependências

Python 3.10+ e a biblioteca [Scapy](https://scapy.net/):

```bash
pip install scapy
```

> **Nota:** A captura de pacotes numa interface real requer permissões de root/administrador.

---

## Estrutura do Projeto

```
sniffer/
├── sniffer.py   — Ponto de entrada, CLI, loop de captura
├── parser.py    — Parsing e identificação de protocolos
├── filters.py   — Lógica de filtragem de pacotes
├── logger.py    — Logging para ficheiro (.txt/.csv/.json)
└── README.md    — Este ficheiro
```

---

## Protocolos Suportados

| Camada       | Protocolos                          |
|-------------|-------------------------------------|
| 2 (Ligação) | Ethernet, ARP                       |
| 3 (Rede)    | IPv4, IPv6, ICMP, ICMPv6            |
| 4 (Transporte) | TCP, UDP                         |
| 7 (Aplicação) | DNS, HTTP, DHCP                   |

---

## Como Executar

### 1. Listar interfaces disponíveis

```bash
python3 sniffer.py --list
```

### 2. Captura simples (modo live)

```bash
sudo python3 sniffer.py -i eth0
```

### 3. Filtrar por protocolo

```bash
sudo python3 sniffer.py -i eth0 --proto TCP
sudo python3 sniffer.py -i eth0 --proto DNS
sudo python3 sniffer.py -i eth0 --proto ARP
```

### 4. Filtrar por IP ou MAC

```bash
sudo python3 sniffer.py -i eth0 --ip 192.168.1.1
sudo python3 sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```

### 5. Filtro BPF (Berkeley Packet Filter)

```bash
sudo python3 sniffer.py -i eth0 --bpf "tcp port 80"
sudo python3 sniffer.py -i eth0 --bpf "udp port 53"
sudo python3 sniffer.py -i eth0 --bpf "host 192.168.1.1"
```

### 6. Guardar log em ficheiro

```bash
sudo python3 sniffer.py -i eth0 --log captura.txt
sudo python3 sniffer.py -i eth0 --log captura.csv
sudo python3 sniffer.py -i eth0 --log captura.json
```

### 7. Modo log apenas (sem impressão no terminal)

```bash
sudo python3 sniffer.py -i eth0 --no-live --log captura.csv
```

### 8. Limitar número de pacotes

```bash
sudo python3 sniffer.py -i eth0 --count 100
```

### 9. Combinações

```bash
# Capturar 50 pacotes TCP, guardar em CSV e mostrar no terminal
sudo python3 sniffer.py -i eth0 --proto TCP --count 50 --log tcp_cap.csv

# Filtrar tráfego de um IP específico, guardar em JSON
sudo python3 sniffer.py -i wlan0 --ip 8.8.8.8 --log dns_google.json
```

---

## Executar no CORE

1. Abrir o CORE e criar a topologia desejada.
2. Fazer duplo clique num nó para abrir o terminal.
3. Navegar para a pasta do sniffer e executar:

```bash
cd /path/to/sniffer
python3 sniffer.py -i eth0
```

> No CORE, os nós correm como root — não é necessário `sudo`.

---

## Parâmetros Disponíveis

| Parâmetro          | Descrição                                           |
|--------------------|-----------------------------------------------------|
| `-i`, `--iface`    | Interface de rede (obrigatório)                     |
| `--list`           | Lista interfaces disponíveis                        |
| `--proto PROTO`    | Filtrar por protocolo                               |
| `--ip IP`          | Filtrar por endereço IP                             |
| `--mac MAC`        | Filtrar por endereço MAC                            |
| `--bpf EXPR`       | Expressão BPF para filtro ao nível do kernel        |
| `--log FICHEIRO`   | Guardar em ficheiro (.txt/.csv/.json)               |
| `--no-live`        | Não imprimir no terminal (requer `--log`)           |
| `--count N`        | Parar após N pacotes (0 = infinito)                 |

---

## Parar a Captura

Pressionar **Ctrl+C** termina graciosamente a captura e exibe estatísticas.
