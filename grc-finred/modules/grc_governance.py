"""
Autor: Brizeth Jazmin Alvarado Lopez
Fecha: 2026-06-02
Descripcion: Evaluación de KPIs, KRIs y score de madurez por marco GRC para FinRed Guatemala.
             Cubre gobierno de TI (ISO 27001, COBIT 2019, NIST CSF 2.0).
"""

from __future__ import annotations

from common.models import KPI, KRI
from common.reporting import finding, load_json, print_findings, print_section, status_badge, write_json

FRAMEWORKS = ["ISO27001", "COBIT", "NIST"]

_NIST_FUNCTIONS = {"Identify", "Protect", "Detect", "Respond", "Recover"}

_MATURITY_LEVELS = [
    (85, "Optimizado"),
    (70, "Gestionado"),
    (50, "Definido"),
    (30, "Inicial"),
    (0,  "Crítico"),
]


def load_kpis() -> list[KPI]:
    """Carga KPIs desde data/kpi_kri.json."""
    raw = load_json("kpi_kri.json")
    return [
        KPI(
            id=k["id"],
            name=k["name"],
            definition=k["definition"],
            target=k["target"],
            target_value=k["target_value"],
            current_value=k["current_value"],
            unit=k["unit"],
            frequency=k["frequency"],
            owner=k["owner"],
        )
        for k in raw["kpis"]
    ]


def load_kris() -> list[KRI]:
    """Carga KRIs desde data/kpi_kri.json."""
    raw = load_json("kpi_kri.json")
    return [
        KRI(
            id=k["id"],
            name=k["name"],
            risk_ref=k["risk_ref"],
            threshold=k["threshold"],
            current_value=k["current_value"],
            frequency=k["frequency"],
            owner=k["owner"],
        )
        for k in raw["kris"]
    ]


def framework_score(controls: list[dict], framework: str) -> int:
    """
    Score de cumplimiento por marco = controles implementados / total del marco × 100.
    Alineado con evaluación de madurez de NIST CSF Tier e ISO 27001 Annex A.
    """
    fw_controls = [c for c in controls if framework in c["framework"]]
    if not fw_controls:
        return 0
    implemented = sum(1 for c in fw_controls if c["implemented"])
    return round(implemented / len(fw_controls) * 100)


def maturity_label(score: int) -> str:
    """Convierte score a nivel de madurez GRC."""
    for threshold, label in _MATURITY_LEVELS:
        if score >= threshold:
            return label
    return "Crítico"


def nist_function_coverage(controls: list[dict]) -> dict[str, dict]:
    """
    Evalúa cobertura por función NIST CSF 2.0 (Identify/Protect/Detect/Respond/Recover).
    Retorna dict con score y estado por función.
    """
    result = {}
    for fn in _NIST_FUNCTIONS:
        fn_controls = [c for c in controls if c["domain"] == fn]
        if not fn_controls:
            result[fn] = {"score": 0, "implemented": 0, "total": 0}
            continue
        implemented = sum(1 for c in fn_controls if c["implemented"])
        score = round(implemented / len(fn_controls) * 100)
        result[fn] = {"score": score, "implemented": implemented, "total": len(fn_controls)}
    return result


def generate_kpi_findings(kpis: list[KPI]) -> list[dict]:
    """Genera hallazgos para KPIs en estado ROJO (incumplimiento de meta)."""
    findings = []
    for kpi in kpis:
        if kpi.status != "ROJO":
            continue
        findings.append(
            finding(
                framework="ISO27001",
                domain="KPI — Gobierno GRC",
                title=f"{kpi.id} fuera de meta: {kpi.name}",
                evidence=f"Actual {kpi.current_value}{kpi.unit} vs meta {kpi.target} | Freq: {kpi.frequency}",
                impact="Incumplimiento sostenido indica control sin efectividad operativa",
                recommendation=f"Escalar a {kpi.owner} para plan de acción; meta a cubrir en próximo ciclo",
                severity="high",
            )
        )
    return findings


def generate_kri_findings(kris: list[KRI]) -> list[dict]:
    """Genera hallazgos críticos para KRIs que superan umbral de alerta."""
    findings = []
    for kri in kris:
        if kri.status != "CRITICO":
            continue
        findings.append(
            finding(
                framework="NIST",
                domain="KRI — Monitoreo de Riesgo",
                title=f"{kri.id} supera umbral: {kri.name}",
                evidence=f"Valor actual {kri.current_value} | Umbral {kri.threshold} | Riesgo {kri.risk_ref}",
                impact="KRI disparado indica materialización o inminencia de escenario de riesgo",
                recommendation=f"Activar protocolo de respuesta inmediata; responsable: {kri.owner}",
                severity="critical",
            )
        )
    return findings


def analyze() -> tuple[list[dict], dict]:
    """
    Evalúa KPIs, KRIs y scores de madurez por marco GRC.
    Retorna (findings, governance_report).
    """
    kpis = load_kpis()
    kris = load_kris()
    controls_raw = load_json("controls.json")

    kpi_findings = generate_kpi_findings(kpis)
    kri_findings = generate_kri_findings(kris)
    all_findings = kpi_findings + kri_findings

    framework_scores = {fw: framework_score(controls_raw, fw) for fw in FRAMEWORKS}
    avg_score = round(sum(framework_scores.values()) / len(framework_scores))

    report = {
        "kpis": [
            {
                "id": k.id, "name": k.name,
                "target": k.target,
                "current": k.current_value,
                "unit": k.unit,
                "status": k.status,
                "owner": k.owner,
            }
            for k in kpis
        ],
        "kris": [
            {
                "id": k.id, "name": k.name,
                "threshold": k.threshold,
                "current": k.current_value,
                "status": k.status,
                "risk_ref": k.risk_ref,
                "owner": k.owner,
            }
            for k in kris
        ],
        "framework_scores": framework_scores,
        "nist_functions": nist_function_coverage(controls_raw),
        "average_score": avg_score,
        "maturity_level": maturity_label(avg_score),
    }
    return all_findings, report


def print_summary(report: dict) -> None:
    """Imprime estado de KPIs, KRIs y scores de madurez por marco."""
    print_section("GOBIERNO GRC — KPIs / KRIs / MADUREZ")

    print("  KPIs DE DESEMPEÑO:")
    print(f"  {'ID':<8}  {'KPI':<38}  {'Actual':>8}  {'Meta':<12}  Estado")
    print(f"  {'─'*78}")
    for k in report["kpis"]:
        badge = status_badge(k["status"])
        val = f"{k['current']}{k['unit']}"
        print(f"  {k['id']:<8}  {k['name'][:38]:<38}  {val:>8}  {k['target']:<12}  {badge}")
    print()

    print("  KRIs DE RIESGO:")
    print(f"  {'ID':<8}  {'KRI':<42}  {'Valor':>6}  {'Umbral':>7}  Estado")
    print(f"  {'─'*78}")
    for k in report["kris"]:
        badge = status_badge(k["status"])
        print(f"  {k['id']:<8}  {k['name'][:42]:<42}  {k['current']:>6.0f}  {k['threshold']:>7.0f}  {badge}")
    print()

    print("  MADUREZ GRC POR MARCO:")
    for fw, score in report["framework_scores"].items():
        mlabel = maturity_label(score)
        badge = status_badge(mlabel)
        print(f"  {fw:<12}  {score:>3}%  {badge}")
    print(f"\n  Promedio GRC: {report['average_score']}% — {status_badge(report['maturity_level'])}\n")

    print("  COBERTURA NIST CSF 2.0:")
    for fn, data in report["nist_functions"].items():
        score = data["score"]
        mlabel = maturity_label(score)
        badge = status_badge(mlabel)
        print(f"  {fn:<10}  {score:>3}%  ({data['implemented']}/{data['total']})  {badge}")
    print()


def main() -> None:
    findings, report = analyze()
    print_summary(report)
    print_findings(findings)
    write_json("grc_governance.json", {"findings": findings, "report": report})
    print(f"  Output: outputs/grc_governance.json\n")


if __name__ == "__main__":
    main()
