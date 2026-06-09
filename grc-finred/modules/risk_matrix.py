"""
Autor: Miguel Estuardo Samayoa Giron
Fecha: 2026-05-27
Descripcion: Motor de análisis de riesgos inherentes y residuales para FinRed Guatemala.
             Implementa metodología ISO/IEC 27005:2022 con matriz de calor 5x5.
"""

from __future__ import annotations

from common.models import RiskScenario, classify_score
from common.reporting import finding, load_json, print_findings, print_section, status_badge, write_json


RISK_LEVEL_ORDER = {"MUY ALTO": 5, "ALTO": 4, "MEDIO": 3, "BAJO": 2, "MUY BAJO": 1}


def load_scenarios() -> list[RiskScenario]:
    """Carga registro de riesgos desde data/risk_registry.json."""
    raw = load_json("risk_registry.json")
    return [
        RiskScenario(
            id=r["id"],
            asset_id=r["asset_id"],
            threat=r["threat"],
            vector=r["vector"],
            tactic_id=r["tactic_id"],
            technique_id=r["technique_id"],
            mitre_id=r["mitre_id"],
            likelihood=r["likelihood"],
            impact=r["impact"],
            control_effectiveness=r["control_effectiveness"],
            control_ids=r.get("control_ids", []),
        )
        for r in raw
    ]


def distribution(scenarios: list[RiskScenario], use_residual: bool = False) -> dict[str, int]:
    """Cuenta escenarios por nivel de riesgo (inherente o residual)."""
    counts: dict[str, int] = {"MUY ALTO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "MUY BAJO": 0}
    for s in scenarios:
        level = s.residual_level if use_residual else s.inherent_level
        counts[level] = counts.get(level, 0) + 1
    return counts


def top_risks(scenarios: list[RiskScenario], n: int = 10) -> list[RiskScenario]:
    """Retorna los N escenarios con mayor score inherente."""
    return sorted(scenarios, key=lambda s: s.inherent_score, reverse=True)[:n]


def build_heatmap(scenarios: list[RiskScenario]) -> dict:
    """
    Construye matriz de calor 5x5 con conteo de escenarios por celda (P, I).
    Retorna dict { (p, i): count } serializado como lista para JSON.
    """
    matrix: dict[tuple[int, int], int] = {}
    for s in scenarios:
        key = (s.likelihood, s.impact)
        matrix[key] = matrix.get(key, 0) + 1
    return [{"p": k[0], "i": k[1], "count": v} for k, v in sorted(matrix.items())]


def generate_findings(scenarios: list[RiskScenario]) -> list[dict]:
    """Genera hallazgos GRC para escenarios inherentes ALTO y MUY ALTO."""
    findings = []
    for s in scenarios:
        if s.inherent_level not in ("ALTO", "MUY ALTO"):
            continue
        severity = "critical" if s.inherent_level == "MUY ALTO" else "high"
        findings.append(
            finding(
                framework="ISO27001",
                domain="Gestión de Riesgos",
                title=f"{s.id} — {s.threat[:60]}",
                evidence=f"Score inherente {s.inherent_score} ({s.inherent_level}) | {s.asset_id} | {s.mitre_id}",
                impact=f"Vector {s.vector}; tactic {s.tactic_id}; técnica {s.technique_id}",
                recommendation=f"Aplicar controles: {', '.join(s.control_ids)} — efectividad proyectada {s.control_effectiveness*100:.0f}%",
                severity=severity,
            )
        )
    return findings


def analyze() -> tuple[list[dict], dict]:
    """
    Ejecuta análisis completo de riesgo inherente y residual.
    Retorna (findings, stats) donde stats incluye distribuciones y heat map.
    """
    scenarios = load_scenarios()
    findings = generate_findings(scenarios)

    inherent_dist = distribution(scenarios, use_residual=False)
    residual_dist = distribution(scenarios, use_residual=True)
    top = top_risks(scenarios, n=5)

    stats = {
        "total_scenarios": len(scenarios),
        "inherent_distribution": inherent_dist,
        "residual_distribution": residual_dist,
        "heatmap": build_heatmap(scenarios),
        "top_5_inherent": [
            {
                "id": s.id,
                "asset_id": s.asset_id,
                "threat": s.threat[:70],
                "vector": s.vector,
                "inherent_score": s.inherent_score,
                "inherent_level": s.inherent_level,
                "residual_score": round(s.residual_score, 1),
                "residual_level": s.residual_level,
                "control_effectiveness_pct": round(s.control_effectiveness * 100),
            }
            for s in top
        ],
    }
    return findings, stats


def print_summary(stats: dict) -> None:
    """Imprime resumen de distribución de riesgos en consola."""
    print_section("ANÁLISIS DE RIESGOS — ISO/IEC 27005:2022")
    print(f"  Total escenarios: {stats['total_scenarios']}\n")

    print(f"  {'Nivel':<10}  {'Inherente':>10}  {'Residual':>10}")
    print(f"  {'─'*36}")
    for level in ["MUY ALTO", "ALTO", "MEDIO", "BAJO", "MUY BAJO"]:
        inh = stats["inherent_distribution"].get(level, 0)
        res = stats["residual_distribution"].get(level, 0)
        badge = status_badge(level)
        print(f"  {badge:<25}  {inh:>10}  {res:>10}")
    print()

    print("  TOP 5 RIESGOS INHERENTES:")
    print(f"  {'─'*70}")
    for r in stats["top_5_inherent"]:
        badge = status_badge(r["inherent_level"])
        print(f"  {r['id']}  {badge:<25}  {r['vector']:<12}  {r['threat'][:42]}")
    print()


def main() -> None:
    findings, stats = analyze()
    print_summary(stats)
    print_findings(findings)
    write_json("risk_analysis.json", {"findings": findings, "stats": stats})
    print(f"  Output: outputs/risk_analysis.json\n")


if __name__ == "__main__":
    main()
