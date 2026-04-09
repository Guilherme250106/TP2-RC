"""
logger.py — Módulo de logging do Packet Sniffer
Responsável por guardar pacotes capturados em ficheiro (.txt, .csv ou .json).
Suporta os três formatos e pode estar ativo simultaneamente com o modo live.
"""

import csv
import json
import os
from datetime import datetime


class PacketLogger:
    """
    Gere a escrita de pacotes capturados para ficheiro.
    Suporta formatos: 'txt', 'csv', 'json'.
    O ficheiro é aberto em modo append, permitindo sessões contínuas.
    """

    # Cabeçalhos das colunas para o formato CSV
    CSV_FIELDS = [
        "timestamp", "interface", "protocol",
        "src_mac", "dst_mac", "src_ip", "dst_ip",
        "size", "summary"
    ]

    def __init__(self, filepath: str):
        """
        Args:
            filepath (str): Caminho para o ficheiro de log.
                            A extensão determina o formato (.txt/.csv/.json).

        Raises:
            ValueError: Se a extensão não for suportada.
        """
        self.filepath = filepath
        self.fmt = os.path.splitext(filepath)[1].lstrip(".").lower()

        if self.fmt not in ("txt", "csv", "json"):
            raise ValueError(f"Formato '{self.fmt}' não suportado. Use .txt, .csv ou .json")

        # Para JSON, acumulamos todos os registos numa lista e reescrevemos
        # no final (ou periodicamente), garantindo JSON válido.
        self._json_buffer = []

        # Abrir/criar ficheiro e escrever cabeçalho se necessário
        self._init_file()

    def _init_file(self):
        """Cria o ficheiro e escreve cabeçalho inicial conforme o formato."""
        if self.fmt == "csv":
            # Só escrevemos o cabeçalho se o ficheiro for novo/vazio
            file_exists = os.path.isfile(self.filepath) and os.path.getsize(self.filepath) > 0
            self._csv_file = open(self.filepath, "a", newline="", encoding="utf-8")
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=self.CSV_FIELDS)
            if not file_exists:
                self._csv_writer.writeheader()

        elif self.fmt == "txt":
            self._txt_file = open(self.filepath, "a", encoding="utf-8")
            # Escreve separador de sessão com data/hora
            self._txt_file.write(
                f"\n{'='*70}\n"
                f"  Sessão iniciada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'='*70}\n"
            )

        elif self.fmt == "json":
            # Se o ficheiro já existe, carregamos os dados anteriores
            if os.path.isfile(self.filepath) and os.path.getsize(self.filepath) > 0:
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        self._json_buffer = json.load(f)
                except (json.JSONDecodeError, IOError):
                    self._json_buffer = []

    def log(self, parsed: dict):
        """
        Escreve um pacote no ficheiro de log.

        Args:
            parsed (dict): Dicionário com os campos do pacote parseado.
        """
        if self.fmt == "txt":
            line = (
                f"[{parsed.get('timestamp','')}] "
                f"{parsed.get('interface','?'):10s} | "
                f"{parsed.get('protocol','?'):20s} | "
                f"{parsed.get('src_mac','?')} -> {parsed.get('dst_mac','?')} | "
                f"{parsed.get('src_ip',''):15s} -> {parsed.get('dst_ip',''):15s} | "
                f"{parsed.get('size',0):5d} bytes | "
                f"{parsed.get('summary','')}\n"
            )
            self._txt_file.write(line)
            self._txt_file.flush()  # Garantir escrita imediata (útil em live)

        elif self.fmt == "csv":
            row = {field: parsed.get(field, "") for field in self.CSV_FIELDS}
            self._csv_writer.writerow(row)
            self._csv_file.flush()

        elif self.fmt == "json":
            self._json_buffer.append(parsed)
            # Reescrevemos o ficheiro a cada pacote (simples, mas correto)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self._json_buffer, f, indent=2, ensure_ascii=False)

    def close(self):
        """Fecha o ficheiro de log corretamente."""
        if self.fmt == "txt" and hasattr(self, "_txt_file"):
            self._txt_file.write(
                f"{'='*70}\n"
                f"  Sessão terminada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'='*70}\n"
            )
            self._txt_file.close()
        elif self.fmt == "csv" and hasattr(self, "_csv_file"):
            self._csv_file.close()
        # JSON já é fechado a cada escrita

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
