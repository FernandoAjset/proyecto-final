"""
Autor: Edgar Fernando Ajset Nimacache
Fecha: 2026-06-04
Descripcion: Orquestador del programa GRC de FinRed Guatemala.
             Ejecuta todos los módulos de análisis y genera reporte integrado.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime

from common.reporting import (
    BOLD, CYAN, GREEN, RED, RESET, YELLOW,
    build_run_header, print_section, write_json, write_text,
)
from modules.grc_governance import analyze as analyze_governance
from modules.risk_matrix import analyze as analyze_risk
from modules.threat_intel import analyze as analyze_threats
from modules.zt_maturity import analyze as analyze_zt


_MODULES = [
    ("Análisis de Riesgos",       analyze_risk,       "risk_analysis.json"),
    ("Threat Intelligence",        analyze_threats,    "threat_intel.json"),
    ("Madurez Zero Trust",         analyze_zt,         "zt_maturity.json"),
    ("Gobierno GRC (KPI/KRI)",     analyze_governance, "grc_governance.json"),
]


def run_module(name: str, fn, output_file: str) -> tuple[list[dict], dict]:
    """
    Ejecuta un módulo de análisis, captura sus resultados y reporta estado.
    Retorna (findings, stats) del módulo.
    """
    print(f"\n{CYAN}▶  {name}{RESET}")
    try:
        findings, stats = fn()
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        print(f"   {GREEN}✓{RESET}  {len(findings)} hallazgos — {RED}{critical} críticos{RESET}, {YELLOW}{high} altos{RESET}")
        return findings, stats
    except Exception as exc:
        print(f"   {RED}✗  Error en {name}: {exc}{RESET}")
        return [], {}


def aggregate_findings(all_results: list[tuple[list[dict], dict]]) -> list[dict]:
    """Consolida hallazgos de todos los módulos en lista única."""
    combined = []
    for findings, _ in all_results:
        combined.extend(findings)
    return combined


def build_master_report(all_results: list[tuple[list[dict], dict]], all_findings: list[dict]) -> str:
    """
    Genera texto del reporte GRC integrado con resumen ejecutivo y estadísticas.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    critical = [f for f in all_findings if f["severity"] == "critical"]
    high = [f for f in all_findings if f["severity"] == "high"]
    medium = [f for f in all_findings if f["severity"] == "medium"]

    lines = [
        build_run_header([m[0] for m in _MODULES]),
        "",
        "─" * 70,
        "RESUMEN EJECUTIVO",
        "─" * 70,
        f"  Total hallazgos: {len(all_findings)}",
        f"  Críticos:        {len(critical)}",
        f"  Altos:           {len(high)}",
        f"  Medios:          {len(medium)}",
        "",
        "TOP HALLAZGOS CRÍTICOS:",
    ]
    for f in critical[:8]:
        lines.append(f"  [{f['severity'].upper():8}]  {f['framework']} / {f['domain']}")
        lines.append(f"             {f['title']}")
        lines.append("")

    lines.append("─" * 70)
    lines.append(f"Reporte generado: {ts}")
    return "\n".join(lines)


def build_dashboard_payload(all_results: list[tuple[list[dict], dict]]) -> dict:
    """
    Construye payload JSON para el dashboard HTML con datos de todos los módulos.
    Fusiona con dashboard_data.json del incidente si existe.
    """
    risk_findings, risk_stats     = all_results[0]
    _,             threat_data    = all_results[1]
    _,             zt_data        = all_results[2]
    _,             gov_data       = all_results[3]

    payload = {
        "generated_at": datetime.now().isoformat(),
        "risk_analysis": risk_stats,
        "threat_intel":  threat_data,
        "zt_maturity":   zt_data,
        "governance":    gov_data,
    }

    # Fusión con datos del incidente IR-2026-0601 si ya fue ejecutado
    try:
        import os
        incident_path = os.path.join("outputs", "dashboard_data.json")
        with open(incident_path, encoding="utf-8") as f:
            payload["incident"] = json.load(f)
    except FileNotFoundError:
        payload["incident"] = None

    return payload


def print_final_summary(all_findings: list[dict]) -> None:
    """Imprime tabla final con conteo de hallazgos por módulo y severidad."""
    print_section("RESUMEN INTEGRADO DEL PROGRAMA GRC")
    total = len(all_findings)
    by_severity = {}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    print(f"  Total hallazgos: {BOLD}{total}{RESET}\n")
    for sev in ("critical", "high", "medium", "low"):
        count = by_severity.get(sev, 0)
        if count:
            color = RED if sev == "critical" else (YELLOW if sev == "high" else "")
            print(f"  {color}{sev.upper():<10}{RESET}  {count}")
    print()


def main() -> None:
    print(f"\n{CYAN}{BOLD}{'═' * 70}{RESET}")
    print(f"{CYAN}{BOLD}  FinRed Guatemala, S.A. — Programa GRC{RESET}")
    print(f"{CYAN}{BOLD}  Análisis Integrado de Gobierno, Riesgo y Cumplimiento{RESET}")
    print(f"{CYAN}{BOLD}{'═' * 70}{RESET}")

    all_results = []
    for name, fn, output in _MODULES:
        result = run_module(name, fn, output)
        all_results.append(result)

    all_findings = aggregate_findings(all_results)

    print_final_summary(all_findings)

    report_text = build_master_report(all_results, all_findings)
    write_text("reporte_integrado_grc.txt", report_text)

    dashboard_payload = build_dashboard_payload(all_results)
    write_json("grc_full_report.json", dashboard_payload)

    print(f"  {GREEN}Archivos generados:{RESET}")
    print(f"    ✓  outputs/reporte_integrado_grc.txt")
    print(f"    ✓  outputs/grc_full_report.json")
    print(f"    ✓  outputs/risk_analysis.json")
    print(f"    ✓  outputs/threat_intel.json")
    print(f"    ✓  outputs/zt_maturity.json")
    print(f"    ✓  outputs/grc_governance.json")
    print()

    critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
    if critical_count:
        print(f"  {RED}{BOLD}⚠  {critical_count} hallazgos críticos requieren acción inmediata.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
