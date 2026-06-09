"""
Autor: Edgar Fernando Ajset Nimacache
Fecha: 2026-05-19
Descripcion: Modelos de datos centrales del programa GRC de FinRed Guatemala.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Asset:
    """Activo crítico de FinRed Guatemala (ACT-XX)."""
    id: str
    name: str
    environment: str
    asset_type: str
    exposure: str
    classification: str       # confidential | internal | public | unclassified
    criticality: str          # critical | high | medium | low
    mfa_required: bool
    mfa_enabled: bool
    likelihood: int           # 1-5
    impact: int               # 1-5
    owner: str

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def risk_level(self) -> str:
        return classify_score(self.risk_score)


@dataclass
class RiskScenario:
    """Escenario de riesgo individual del registro RIE-XX."""
    id: str
    asset_id: str
    threat: str
    vector: str               # Ransomware | Phishing | APT | Insider
    tactic_id: str            # TA-XX
    technique_id: str         # TE-XX
    mitre_id: str             # T1XXX
    likelihood: int           # 1-5
    impact: int               # 1-5
    control_effectiveness: float  # 0.0-1.0
    control_ids: list[str] = field(default_factory=list)

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def inherent_level(self) -> str:
        return classify_score(self.inherent_score)

    @property
    def residual_score(self) -> float:
        return self.inherent_score * (1 - self.control_effectiveness)

    @property
    def residual_level(self) -> str:
        return classify_score(int(self.residual_score))


@dataclass
class Control:
    """Control de seguridad implementado o propuesto (CTR-XX)."""
    id: str
    name: str
    framework: str            # ISO27001 | COBIT | NIST | ISO27001/NIST | etc.
    domain: str               # Identify | Protect | Detect | Respond | Recover
    pillar_zt: str            # Identity | Device | Network | Application | Data
    implemented: bool
    evidence: str
    cost_q: int               # Costo anual en Quetzales


@dataclass
class KPI:
    """Indicador clave de desempeño del programa GRC."""
    id: str
    name: str
    definition: str
    target: str               # Meta expresada como string (porcentaje, horas, etc.)
    target_value: float       # Meta numérica para comparación
    current_value: float
    unit: str                 # % | horas | count
    frequency: str
    owner: str

    @property
    def status(self) -> str:
        """Verde / Amarillo / Rojo según proximidad a meta."""
        pct = self.current_value / self.target_value if self.target_value else 0
        # KPIs donde menos es mejor (tiempos)
        if self.unit == "horas":
            if self.current_value <= self.target_value:
                return "VERDE"
            if self.current_value <= self.target_value * 1.5:
                return "AMARILLO"
            return "ROJO"
        # KPIs donde más es mejor (porcentajes, coberturas)
        if pct >= 1.0:
            return "VERDE"
        if pct >= 0.85:
            return "AMARILLO"
        return "ROJO"


@dataclass
class KRI:
    """Indicador clave de riesgo con umbral de alerta."""
    id: str
    name: str
    risk_ref: str             # RIE-XX vinculado
    threshold: float          # Valor umbral de alerta
    current_value: float
    frequency: str
    owner: str

    @property
    def status(self) -> str:
        """CRITICO si supera umbral, OK si está dentro."""
        if self.current_value > self.threshold:
            return "CRITICO"
        return "OK"


@dataclass
class ThreatActor:
    """Actor de amenaza relevante para el sector fintech de Guatemala."""
    id: str
    name: str
    category: str             # eCrime | APT | RaaS | Insider | IAB
    origin: str
    active: bool
    targets_fintech: bool
    ttps: list[str]           # Lista de T-codes MITRE ATT&CK
    risk_scenario_ids: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Hallazgo GRC producido por cualquier módulo de análisis."""
    framework: str
    domain: str
    title: str
    evidence: str
    impact: str
    recommendation: str
    severity: str             # critical | high | medium | low


def classify_score(score: int) -> str:
    """Clasifica score numérico P×I en nivel de riesgo según metodología FinRed."""
    if score >= 20:
        return "MUY ALTO"
    if score >= 15:
        return "ALTO"
    if score >= 9:
        return "MEDIO"
    if score >= 5:
        return "BAJO"
    return "MUY BAJO"
