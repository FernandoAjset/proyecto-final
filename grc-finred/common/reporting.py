"""
Autor: Edgar Fernando Ajset Nimacache
Fecha: 2026-05-22
Descripcion: Utilidades de salida, impresion coloreada y escritura de reportes GRC.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")
os.makedirs(OUTPUTS_DIR, exist_ok=True)

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
WHITE  = "\033[97m"

_SEVERITY_COLOR = {
    "critical": RED,
    "high":     YELLOW,
    "medium":   WHITE,
    "low":      DIM,
}

_STATUS_COLOR = {
    "VERDE":   GREEN,
    "AMARILLO": YELLOW,
    "ROJO":    RED,
    "CRITICO": RED,
    "OK":      GREEN,
    "MUY ALTO": f"{RED}{BOLD}",
    "ALTO":    YELLOW,
    "MEDIO":   WHITE,
    "BAJO":    GREEN,
    "MUY BAJO": GREEN,
}


def print_section(title: str) -> None:
    """Imprime encabezado de sección con separador visual."""
    print(f"\n{CYAN}{BOLD}{'─' * 70}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─' * 70}{RESET}\n")


def print_finding(f: dict) -> None:
    """Imprime hallazgo individual con color por severidad."""
    color = _SEVERITY_COLOR.get(f["severity"], WHITE)
    label = f["severity"].upper()
    print(f"  {color}[{label:8}]{RESET}  {f['framework']} / {f['domain']}")
    print(f"             {BOLD}{f['title']}{RESET}")
    print(f"             {DIM}Evidencia: {f['evidence'][:80]}{RESET}")
    print(f"             Impacto:  {f['impact'][:80]}")
    print(f"             {GREEN}Rec:      {f['recommendation'][:80]}{RESET}")
    print()


def print_findings(findings: list[dict]) -> None:
    """Imprime lista de hallazgos ordenados por severidad."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        print_finding(f)


def status_badge(status: str) -> str:
    """Retorna string coloreado para estado KPI/KRI/riesgo."""
    color = _STATUS_COLOR.get(status, WHITE)
    return f"{color}{BOLD}{status}{RESET}"


def finding(
    framework: str,
    domain: str,
    title: str,
    evidence: str,
    impact: str,
    recommendation: str,
    severity: str,
) -> dict:
    """Construye dict estándar de hallazgo GRC."""
    return {
        "framework": framework,
        "domain": domain,
        "title": title,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "severity": severity,
    }


def write_json(filename: str, data: Any) -> str:
    """Escribe objeto como JSON en outputs/. Retorna ruta del archivo."""
    path = os.path.join(OUTPUTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def write_text(filename: str, content: str) -> str:
    """Escribe texto plano en outputs/. Retorna ruta del archivo."""
    path = os.path.join(OUTPUTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def load_json(data_filename: str) -> Any:
    """Carga JSON desde directorio data/ del proyecto."""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    path = os.path.join(data_dir, data_filename)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_run_header(modules_run: list[str]) -> str:
    """Genera encabezado de ejecución para reporte maestro."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "╔══════════════════════════════════════════════════════════════════════╗",
        "║  FinRed Guatemala, S.A. — Programa GRC                             ║",
        "║  Reporte Integrado de Análisis GRC                                 ║",
        f"║  Generado: {ts}                              ║",
        "╚══════════════════════════════════════════════════════════════════════╝",
        "",
        "Módulos ejecutados:",
    ]
    for m in modules_run:
        lines.append(f"  ✓ {m}")
    return "\n".join(lines)
