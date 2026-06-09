"""
Autor: Katerine Jireh Franco Recinos
Fecha: 2026-05-28
Descripcion: Correlacion de actores de amenaza con escenarios de riesgo de FinRed Guatemala.
             Mapeo MITRE ATT&CK, scoring de relevancia y priorización de TTPs activos.
"""

from __future__ import annotations

from common.models import ThreatActor
from common.reporting import finding, load_json, print_findings, print_section, status_badge, write_json

_SEVERITY_BY_CATEGORY = {
    "APT":    "critical",
    "RaaS":   "critical",
    "eCrime": "high",
    "IAB":    "high",
    "Insider": "medium",
}

_TACTICS_MAP = {
    "TA-01": "Initial Access",
    "TA-02": "Execution",
    "TA-03": "Persistence",
    "TA-04": "Defense Evasion",
    "TA-05": "Credential Access",
    "TA-06": "Lateral Movement",
    "TA-07": "Exfiltration",
    "TA-08": "Impact",
}


def load_actors() -> list[ThreatActor]:
    """Carga actores de amenaza desde data/threat_actors.json."""
    raw = load_json("threat_actors.json")
    return [
        ThreatActor(
            id=a["id"],
            name=a["name"],
            category=a["category"],
            origin=a["origin"],
            active=a["active"],
            targets_fintech=a["targets_fintech"],
            ttps=a["ttps"],
            risk_scenario_ids=a.get("risk_scenario_ids", []),
        )
        for a in raw
    ]


def load_scenario_index() -> dict[str, dict]:
    """Carga registro de riesgos indexado por ID para lookups rápidos."""
    raw = load_json("risk_registry.json")
    return {r["id"]: r for r in raw}


def actor_relevance_score(actor: ThreatActor) -> int:
    """
    Calcula score de relevancia del actor para FinRed Guatemala (0-100).
    Considera: activo, sector fintech, categoría y cantidad de TTPs cubiertos.
    """
    score = 0
    if actor.active:
        score += 30
    if actor.targets_fintech:
        score += 30
    category_bonus = {"APT": 25, "RaaS": 25, "eCrime": 20, "IAB": 15, "Insider": 10}
    score += category_bonus.get(actor.category, 5)
    ttp_coverage = min(len(actor.ttps) * 2, 15)
    score += ttp_coverage
    return min(score, 100)


def correlate_actor_scenarios(actor: ThreatActor, scenario_index: dict[str, dict]) -> list[dict]:
    """
    Retorna escenarios de riesgo vinculados al actor con datos de correlación.
    Cruza risk_scenario_ids del actor con el registro para obtener detalles.
    """
    correlated = []
    for rid in actor.risk_scenario_ids:
        if rid in scenario_index:
            s = scenario_index[rid]
            correlated.append({
                "risk_id": rid,
                "asset_id": s["asset_id"],
                "threat": s["threat"][:70],
                "vector": s["vector"],
                "mitre_id": s["mitre_id"],
                "inherent_score": s["likelihood"] * s["impact"],
            })
    return sorted(correlated, key=lambda x: x["inherent_score"], reverse=True)


def tactic_coverage(actors: list[ThreatActor]) -> dict[str, list[str]]:
    """
    Retorna qué actores cubren cada táctica MITRE ATT&CK (TA-XX).
    Útil para identificar tácticas sin detección asociada.
    """
    coverage: dict[str, list[str]] = {t: [] for t in _TACTICS_MAP}
    scenario_index = load_scenario_index()
    for actor in actors:
        for rid in actor.risk_scenario_ids:
            if rid in scenario_index:
                tactic = scenario_index[rid]["tactic_id"]
                if actor.name not in coverage.get(tactic, []):
                    coverage.setdefault(tactic, []).append(actor.name)
    return coverage


def generate_findings(actors: list[ThreatActor], scenario_index: dict[str, dict]) -> list[dict]:
    """Genera hallazgos por actor activo que cubre escenarios ALTO o MUY ALTO."""
    findings = []
    for actor in actors:
        if not actor.active:
            continue
        severity = _SEVERITY_BY_CATEGORY.get(actor.category, "medium")
        high_scenarios = [
            rid for rid in actor.risk_scenario_ids
            if rid in scenario_index
            and scenario_index[rid]["likelihood"] * scenario_index[rid]["impact"] >= 15
        ]
        if not high_scenarios:
            continue
        findings.append(
            finding(
                framework="NIST",
                domain="Threat Intelligence",
                title=f"Actor activo con cobertura en escenarios de alto impacto: {actor.name}",
                evidence=f"Categoría: {actor.category} | TTPs: {len(actor.ttps)} | Escenarios ALTO+: {', '.join(high_scenarios[:4])}",
                impact=f"Origen {actor.origin}; relevancia FinRed: {actor_relevance_score(actor)}/100",
                recommendation=f"Priorizar controles: {', '.join(actor.ttps[:4])} — validar feeds CTI contra IOCs activos",
                severity=severity,
            )
        )
    return findings


def analyze() -> tuple[list[dict], dict]:
    """
    Ejecuta análisis de threat intelligence.
    Retorna (findings, landscape) donde landscape incluye actores y cobertura de tácticas.
    """
    actors = load_actors()
    scenario_index = load_scenario_index()
    findings = generate_findings(actors, scenario_index)

    landscape = {
        "actors": [
            {
                "id": a.id,
                "name": a.name,
                "category": a.category,
                "origin": a.origin,
                "active": a.active,
                "relevance_score": actor_relevance_score(a),
                "ttp_count": len(a.ttps),
                "covered_scenarios": len(a.risk_scenario_ids),
                "top_scenarios": correlate_actor_scenarios(a, scenario_index)[:3],
            }
            for a in sorted(actors, key=actor_relevance_score, reverse=True)
        ],
        "tactic_coverage": tactic_coverage(actors),
    }
    return findings, landscape


def print_summary(landscape: dict) -> None:
    """Imprime resumen de actores de amenaza y cobertura táctica."""
    print_section("THREAT INTELLIGENCE — MITRE ATT&CK")
    print(f"  {'Actor':<30}  {'Cat.':<8}  {'Relevan.':<9}  {'TTPs':<6}  {'Escenarios'}")
    print(f"  {'─'*68}")
    for a in landscape["actors"]:
        rel = a["relevance_score"]
        color_label = "CRITICO" if rel >= 80 else ("ALTO" if rel >= 60 else "MEDIO")
        badge = status_badge(color_label)
        print(f"  {a['name']:<30}  {a['category']:<8}  {badge:<25}  {a['ttp_count']:<6}  {a['covered_scenarios']}")
    print()

    print("  COBERTURA POR TÁCTICA (actores que cubren cada fase):")
    for tactic_id, actor_names in landscape["tactic_coverage"].items():
        tname = _TACTICS_MAP.get(tactic_id, tactic_id)
        if actor_names:
            print(f"  {tactic_id} {tname:<25} → {', '.join(actor_names[:3])}")
    print()


def main() -> None:
    findings, landscape = analyze()
    print_summary(landscape)
    print_findings(findings)
    write_json("threat_intel.json", {"findings": findings, "landscape": landscape})
    print(f"  Output: outputs/threat_intel.json\n")


if __name__ == "__main__":
    main()
