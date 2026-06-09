"""
Autor: Katerine Jireh Franco Recinos
Fecha: 2026-05-30
Descripcion: Evaluación de madurez de Arquitectura Zero Trust para FinRed Guatemala.
             Evalúa cinco pilares ZT según NIST SP 800-207 y puntúa por controles implementados.
"""

from __future__ import annotations

from common.reporting import finding, load_json, print_findings, print_section, status_badge, write_json

# Pilares ZT según NIST SP 800-207, mapeados a dominios del programa GRC
ZT_PILLARS = {
    "Identity":    {"label": "Identidad (IAM/PAM/MFA)", "target_controls": ["CTR-02", "CTR-03"]},
    "Device":      {"label": "Dispositivo (EDR/NDR)",   "target_controls": ["CTR-01", "CTR-10"]},
    "Network":     {"label": "Red (Microseg./ZTNA)",    "target_controls": ["CTR-06", "CTR-10", "CTR-08"]},
    "Application": {"label": "Aplicación (DLP/Sandbox)","target_controls": ["CTR-04", "CTR-05", "CTR-11"]},
    "Data":        {"label": "Datos (WORM/DLP)",        "target_controls": ["CTR-07", "CTR-05"]},
}

_MATURITY_LEVELS = [
    (85, "Optimizado"),
    (70, "Gestionado"),
    (50, "Definido"),
    (30, "Inicial"),
    (0,  "Crítico"),
]


def load_controls() -> dict[str, dict]:
    """Carga controles desde data/controls.json indexados por ID."""
    raw = load_json("controls.json")
    return {c["id"]: c for c in raw}


def maturity_label(score: float) -> str:
    """Convierte score numérico (0-100) a nivel de madurez ZT."""
    for threshold, label in _MATURITY_LEVELS:
        if score >= threshold:
            return label
    return "Crítico"


def evaluate_pillar(pillar_name: str, pillar_def: dict, control_index: dict[str, dict]) -> dict:
    """
    Evalúa un pilar ZT calculando el porcentaje de controles objetivo implementados.
    Retorna dict con score, nivel de madurez y detalle de controles.
    """
    target_ids = pillar_def["target_controls"]
    details = []
    implemented_count = 0

    for cid in target_ids:
        ctrl = control_index.get(cid)
        if ctrl is None:
            continue
        implemented = ctrl["implemented"]
        if implemented:
            implemented_count += 1
        details.append({
            "control_id": cid,
            "name": ctrl["name"][:55],
            "implemented": implemented,
            "evidence": ctrl["evidence"][:80],
        })

    score = (implemented_count / len(target_ids) * 100) if target_ids else 0
    return {
        "pillar": pillar_name,
        "label": pillar_def["label"],
        "score": round(score),
        "maturity": maturity_label(score),
        "implemented": implemented_count,
        "total": len(target_ids),
        "controls": details,
    }


def overall_maturity(pillar_results: list[dict]) -> dict:
    """Calcula madurez global ZT como promedio de los cinco pilares."""
    avg = sum(p["score"] for p in pillar_results) / len(pillar_results)
    return {
        "average_score": round(avg),
        "maturity_level": maturity_label(avg),
        "status": _status_label(avg),
    }


def _status_label(score: float) -> str:
    if score >= 70:
        return "GESTIONADO: ZT en madurez operativa"
    if score >= 50:
        return "EN DESARROLLO: controles parciales activos"
    if score >= 30:
        return "INICIAL: brechas críticas en pilares ZT"
    return "CRITICO: arquitectura ZT sin implementación efectiva"


def generate_findings(pillar_results: list[dict]) -> list[dict]:
    """Genera hallazgos para pilares con score inferior a 50% (madurez menor a Definido)."""
    findings = []
    for p in pillar_results:
        if p["score"] >= 50:
            continue
        severity = "critical" if p["score"] < 30 else "high"
        unimplemented = [c["control_id"] for c in p["controls"] if not c["implemented"]]
        findings.append(
            finding(
                framework="NIST",
                domain=f"Zero Trust — {p['pillar']}",
                title=f"Pilar ZT con madurez insuficiente: {p['label']}",
                evidence=f"Score {p['score']}% ({p['implemented']}/{p['total']} controles) | Faltantes: {', '.join(unimplemented)}",
                impact=f"Pilar {p['pillar']} sin controles efectivos expone a vector de entrada no mitigado",
                recommendation=f"Implementar controles pendientes: {', '.join(unimplemented)} — prioridad según roadmap ZT",
                severity=severity,
            )
        )
    return findings


def analyze() -> tuple[list[dict], dict]:
    """
    Evalúa madurez Zero Trust por pilar y calcula score global.
    Retorna (findings, maturity_report).
    """
    control_index = load_controls()
    pillar_results = [
        evaluate_pillar(name, definition, control_index)
        for name, definition in ZT_PILLARS.items()
    ]
    findings = generate_findings(pillar_results)
    maturity = overall_maturity(pillar_results)

    report = {
        "pillars": pillar_results,
        "overall": maturity,
    }
    return findings, report


def print_summary(report: dict) -> None:
    """Imprime tabla de madurez ZT por pilar."""
    print_section("MADUREZ ZERO TRUST — NIST SP 800-207")
    print(f"  {'Pilar':<32}  {'Score':>6}  {'Madurez':<12}  {'Ctrl'}")
    print(f"  {'─'*62}")
    for p in report["pillars"]:
        badge = status_badge(p["maturity"])
        print(f"  {p['label']:<32}  {p['score']:>5}%  {badge:<25}  {p['implemented']}/{p['total']}")
    print()
    overall = report["overall"]
    obadge = status_badge(overall["maturity_level"])
    print(f"  MADUREZ GLOBAL ZT: {overall['average_score']}% — {obadge}")
    print(f"  {overall['status']}\n")


def main() -> None:
    findings, report = analyze()
    print_summary(report)
    print_findings(findings)
    write_json("zt_maturity.json", {"findings": findings, "report": report})
    print(f"  Output: outputs/zt_maturity.json\n")


if __name__ == "__main__":
    main()
