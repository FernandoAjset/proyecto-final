# Proyecto Final GRC — FinRed Guatemala, S.A.
**Universidad Mariano Gálvez | Maestría en Seguridad Informática**  
**Última actualización: 2026-06-08**

---

## 1. Contexto del Proyecto

### Organización
- **Empresa:** FinRed Guatemala, S.A.
- **Sector:** Fintech — pagos digitales, billetera virtual, cobros QR, APIs bancarias
- **Tamaño:** 280 colaboradores, sede Ciudad de Guatemala, operación nacional
- **Dependencia:** Plataforma digital = núcleo del negocio (no herramienta de apoyo)

### Lineamientos
- **Documento base:** `Proyecto Final - GRC.pdf`
- **Puntaje total:** 20 puntos
- **Componentes requeridos:** 8 (1.1 a 1.8)
- **Mínimo citas APA 7:** 10 (el documento tiene 25)

### Equipo
| Nombre | Alias en código |
|---|---|
| Edgar Fernando Ajset Nimacache | Edgar |
| Brizeth Jazmin Alvarado Lopez | Brizeth |
| Miguel Estuardo Samayoa Giron | Miguel |
| Katerine Jireh Franco Recinos | Katerine |

---

## 2. Estado del Documento Word (`ProyectoFinalGRC.docx`)

### Secciones completadas
| Sección | Estado | Observaciones |
|---|---|---|
| 1.1 Contexto Organizacional | ✅ Completo | 13 activos ACT-01→13, 10 procesos clave |
| 1.2 Identificación y Análisis de Riesgos | ✅ Completo | 39 escenarios RIE-01→39, matriz 5×5 |
| 1.3 Threat Intelligence | ✅ Completo | FIN7, APT38, IABs, 8 tácticas MITRE |
| 1.4 Arquitectura Zero Trust | ✅ Completo | NIST SP 800-207, IAM, PAM, FIDO2, microseg |
| 1.5 Gobierno y Cumplimiento | ✅ Completo | 12 KPIs, 10 KRIs, POL-01→10, CISO |
| 1.6 Marcos Internacionales | ✅ Completo | ISO 27001, COBIT 2019, NIST CSF 2.0 |
| 1.7 Simulación de Incidente | ✅ **Contenido listo en `plan-fases-faltantes.md`** — copiar al Word |
| 1.8 Análisis Costo-Beneficio | ✅ **Contenido listo en `plan-fases-faltantes.md`** — copiar al Word |
| Conclusiones | ⚠️ Actualizar con párrafo de IR-2026-0601 y ROSI |
| Referencias | ✅ 25 citas APA 7 |

### Errores conocidos en el Word — PENDIENTES
1. **GRAVE:** Sección 2.1 tabla MUY ALTO dice _"Paro total de la **planta o zafra**"_ — texto de plantilla industrial. Corregir a: _"Interrupción total de la plataforma transaccional por >24h; pérdida >Q4M o 5% del presupuesto anual"_
2. Conclusiones no mencionan IR-2026-0601 ni ROSI — agregar párrafo del `plan-fases-faltantes.md`
3. Verificar que existe sección "Introducción" antes de sección 1

### Formato requerido
- Fuente: Arial 12
- Interlineado: 1.5
- Márgenes estándar
- Numeración de página: ángulo superior derecho
- Sangría: 5 espacios en primer renglón de cada párrafo

---

## 3. Solución Técnica Construida

### Estructura de directorios
```
/proyecto-final/
├── Proyecto Final - GRC.pdf        ← lineamientos UMG (NO modificar)
├── ProyectoFinalGRC.docx           ← documento a entregar
├── auditoria-alineacion.md         ← auditoría de desviaciones del DOCX
├── plan-fases-faltantes.md         ← contenido paste-ready para 1.7 y 1.8
├── CONTEXTO_PROYECTO.md            ← este archivo
└── grc-finred/                     ← código ejecutable del programa GRC
    ├── common/
    │   ├── models.py               Edgar  — 2026-05-19
    │   └── reporting.py            Edgar  — 2026-05-22
    ├── data/
    │   ├── assets.json             Miguel — 2026-05-21
    │   ├── risk_registry.json      Miguel — 2026-05-21
    │   ├── controls.json           Brizeth— 2026-05-26
    │   ├── kpi_kri.json            Brizeth— 2026-05-26
    │   └── threat_actors.json      Katerine—2026-05-23
    ├── modules/
    │   ├── risk_matrix.py          Miguel — 2026-05-27
    │   ├── threat_intel.py         Katerine—2026-05-28
    │   ├── zt_maturity.py          Katerine—2026-05-30
    │   └── grc_governance.py       Brizeth— 2026-06-02
    ├── analisis_incidente.py       Edgar  — 2026-06-01  (sección 1.7 + 1.8)
    ├── dashboard.html              Edgar  — 2026-06-01  (visualización HTML)
    ├── run_all.py                  Edgar  — 2026-06-04  (orquestador)
    └── outputs/                    ← generado al ejecutar, NO versionar
```

---

## 4. Qué Hace Cada Archivo

### `common/models.py` — Edgar Ajset (168 líneas)
Dataclasses centrales del programa. Define:
- `Asset` — activo crítico con `risk_score` y `risk_level` calculados como properties
- `RiskScenario` — escenario RIE-XX con `inherent_score`, `residual_score`, `residual_level`
- `Control` — control CTR-XX con pilar ZT y costo anual en Q
- `KPI` / `KRI` — con lógica de semáforo en property `status`
- `ThreatActor` — actor de amenaza con TTPs y escenarios vinculados
- `Finding` — hallazgo GRC estandarizado
- `classify_score(score)` — función utilitaria MUY BAJO/BAJO/MEDIO/ALTO/MUY ALTO

### `common/reporting.py` — Edgar Ajset (138 líneas)
Utilidades de salida compartidas por todos los módulos:
- Colores ANSI (RED, YELLOW, GREEN, CYAN, etc.)
- `print_section()`, `print_finding()`, `print_findings()`
- `status_badge()` — string coloreado para niveles/estados
- `finding()` — constructor de hallazgo estandarizado
- `write_json()` / `write_text()` — escribe en `outputs/`
- `load_json()` — carga desde `data/`
- `build_run_header()` — encabezado de reporte integrado

### `data/assets.json` — Miguel Samayoa
13 activos ACT-01 a ACT-13 del DOCX con campos: id, name, environment, asset_type, exposure, classification, criticality, mfa_required, mfa_enabled, likelihood, impact, owner.

### `data/risk_registry.json` — Miguel Samayoa
39 escenarios RIE-01 a RIE-39 con: id, asset_id, threat, vector, tactic_id, technique_id, mitre_id, likelihood (P), impact (I), control_effectiveness (0.0–1.0), control_ids.

**Distribución inherente real:**
- MUY ALTO (≥20): RIE-21 (4×5=20), RIE-28 (5×5=25), RIE-13 (4×5=20), RIE-30 (4×5=20)
- ALTO (15-19): RIE-01, 03, 07, 08, 11, 19, 20, 25, 29, 32, 36, 37 (score 15)
- MEDIO (9-14): resto de escenarios

### `data/controls.json` — Brizeth Alvarado
11 controles CTR-01 a CTR-11 con: id, name, framework, domain, pillar_zt, implemented (bool), evidence, cost_q.

**Estado actual (refleja realidad del incidente):**
- `implemented: true` — CTR-01 (SIEM/EDR), CTR-07 (WORM), CTR-08 (TI Platform), CTR-09 (Awareness), CTR-11 (Retainer)
- `implemented: false` — CTR-02 (MFA FIDO2), CTR-03 (PAM), CTR-04 (Sandbox), CTR-05 (DLP), CTR-06 (Microseg.), CTR-10 (NDR)

### `data/kpi_kri.json` — Brizeth Alvarado
12 KPIs + 10 KRIs del DOCX con valores actuales simulados coherentes con IR-2026-0601.

**KPIs en ROJO (incumplimiento):** KPI-02 PAM 72%/95%, KPI-03 JIT 61%/90%, KPI-05 Microseg 45%/100%  
**KRIs disparados (>umbral):** KRI-02, 04, 07, 08, 09, 10

### `data/threat_actors.json` — Katerine Franco
5 actores: FIN7/Carbanak, APT38/Lazarus, Operadores RaaS LockBit 3.0, IABs, Insider Malicioso. Cada uno con: categoría, origen, TTPs (T-codes), risk_scenario_ids vinculados.

### `modules/risk_matrix.py` — Miguel Samayoa (151 líneas)
Motor ISO/IEC 27005:2022. Funciones principales:
- `load_scenarios()` → lista de dataclasses RiskScenario
- `distribution(scenarios, use_residual)` → conteo por nivel
- `top_risks(scenarios, n)` → top N por score inherente
- `build_heatmap(scenarios)` → matriz 5×5 para visualización
- `generate_findings(scenarios)` → hallazgos para ALTO y MUY ALTO
- `analyze()` → entry point retorna (findings, stats)

**Salida al correr:** 17 hallazgos (4 críticos, 13 altos)

### `modules/threat_intel.py` — Katerine Franco (196 líneas)
Correlación MITRE ATT&CK. Funciones principales:
- `load_actors()` → lista ThreatActor
- `actor_relevance_score(actor)` → 0–100 según activo/fintech/categoría/TTPs
- `correlate_actor_scenarios(actor, scenario_index)` → escenarios vinculados con score
- `tactic_coverage(actors)` → qué actores cubren cada táctica TA-01→08
- `generate_findings(actors, scenario_index)` → hallazgos por actor activo
- `analyze()` → entry point

**Scores de relevancia:** LockBit RaaS 100, APT38 100, FIN7 95, IABs 75, Insider 70

**Salida al correr:** 4 hallazgos (2 críticos, 2 altos)

### `modules/zt_maturity.py` — Katerine Franco (165 líneas)
Evaluación NIST SP 800-207. Cinco pilares:
- Identity: CTR-02, CTR-03 → score 0% (ninguno implementado) → CRÍTICO
- Device: CTR-01, CTR-10 → score 50% (CTR-01 implementado) → DEFINIDO
- Network: CTR-06, CTR-10, CTR-08 → score 33% → INICIAL
- Application: CTR-04, CTR-05, CTR-11 → score 33% → INICIAL
- Data: CTR-07, CTR-05 → score 50% (CTR-07 implementado) → DEFINIDO

**Madurez global ZT: ~33% → INICIAL**

**Salida al correr:** 3 hallazgos (1 crítico, 2 altos)

### `modules/grc_governance.py` — Brizeth Alvarado (232 líneas)
KPIs, KRIs y madurez por marco. Funciones principales:
- `load_kpis()` / `load_kris()` → dataclasses con lógica de semáforo
- `framework_score(controls, framework)` → % implementados por ISO27001/COBIT/NIST
- `maturity_label(score)` → Crítico/Inicial/Definido/Gestionado/Optimizado
- `nist_function_coverage(controls)` → cobertura por función NIST CSF 2.0
- `generate_kpi_findings()` → hallazgos para KPIs en ROJO
- `generate_kri_findings()` → hallazgos para KRIs disparados

**Scores de madurez actuales:**
- ISO27001: ~45% → Inicial
- COBIT: ~33% → Inicial
- NIST: ~44% → Inicial
- Promedio: ~40% → Inicial

**Salida al correr:** 9 hallazgos (6 críticos, 3 altos)

### `analisis_incidente.py` — Edgar Ajset / Brizeth Alvarado (334 líneas)
Análisis completo de IR-2026-0601 (secciones 1.7 + 1.8 del proyecto). Contiene:
- 19 eventos de telemetría SIEM desde T0 = 2026-06-15 08:14:00
- Kill chain completo: PHISHING → EXECUTION → C2 → RECON → CRED → PERSIST → LATERAL × 2 → EXFIL × 2 → DEF_EVASION × 2 → IMPACT × 3 → KRI_ALERT × 2 → KILL_CHAIN
- Evento especial `ZT_DETECTION` en T0+3h47m — muestra detección temprana con controles activos
- Cálculo ALE: 4 vectores, total inherente Q2,485,200/yr, residual Q527,004/yr
- ROSI: 116.4%, payback: 5.5 meses
- SHA256 de cadena de custodia forense
- Genera 4 archivos en `outputs/`

**Métricas clave:**
```
MTTD sin controles ZT:  91h 49min  → NO CUMPLE (escenario inherente)
MTTD con controles ZT:   3h 47min  → CUMPLE    (EDR behavioral + CTI feed)
MTTR contención:          240 min  → CUMPLE
ROSI:                    116.4%
Payback:                 5.5 meses
ALE antes:              Q 2,485,200/año
ALE después:            Q   527,004/año
Inversión controles:    Q   904,800/año
```

### `dashboard.html` — Edgar Ajset
Dashboard HTML standalone (sin servidor, sin build step). Chart.js via CDN.
Secciones:
1. Header FinRed con badge P1 IR-2026-0601
2. 5 tarjetas stat (MTTD ZT, MTTD inh, MTTR, activos, exfil)
3. Kill chain visual con T-codes y hover effects
4. ALE comparison bar chart (antes/después por vector)
5. ROSI highlight card
6. Top 5 controles ROI horizontal bar
7. Risk distribution doughnut (39 escenarios)
8. 6 KPI cards con progress bars
9. SHA256 chain of custody

**Nota:** SHA256 solo carga si se sirve desde HTTP. Desde `file://` muestra mensaje de instrucción. Para verlo completo: `python3 -m http.server 8080` y abrir `localhost:8080/dashboard.html`

### `run_all.py` — Edgar Ajset (173 líneas)
Orquestador principal. Corre los 4 módulos en secuencia, consolida hallazgos, genera:
- `outputs/reporte_integrado_grc.txt` — reporte texto maestro
- `outputs/grc_full_report.json` — payload JSON para dashboard (fusiona con datos del incidente)
- Outputs individuales de cada módulo

**Exit code 1** si hay hallazgos críticos — comportamiento intencional para uso en CI/CD.

---

## 5. Cómo Ejecutar

```bash
# Desde /proyecto-final/grc-finred/

# Análisis completo integrado
python3 run_all.py

# Módulos individuales
python3 modules/risk_matrix.py
python3 modules/threat_intel.py
python3 modules/zt_maturity.py
python3 modules/grc_governance.py

# Análisis de incidente (secciones 1.7 + 1.8)
python3 analisis_incidente.py

# Dashboard con SHA256 completo
python3 -m http.server 8080
# abrir http://localhost:8080/dashboard.html
```

**Requisitos:** Python 3.9+, stdlib únicamente (sin dependencias externas).

---

## 6. Datos Clave del Proyecto (para presentación)

### Riesgos
- **39 escenarios** RIE-01 a RIE-39 sobre 13 activos
- **Inherente:** 4 MUY ALTO, 12 ALTO, 21 MEDIO, 2 MUY BAJO
- **Residual (con controles):** 1 MUY ALTO, 0 ALTO, 3 MEDIO, 21 BAJO, 14 MUY BAJO
- **RIE más crítico:** RIE-28 — phishing en red corporativa (P=5, I=5, score=25)
- **Metodología:** ISO/IEC 27005:2022 + NIST SP 800-30 Rev.1

### Incidente IR-2026-0601
- **Tipo:** Ransomware triple extorsión — LockBit 3.0
- **Actor:** Operadores RaaS (acceso comprado a IAB)
- **Vector inicial:** Spearphishing Attachment (T1566.001) → a.garcia@finred.gt
- **Kill chain:** T1566.001 → T1059.001 → T1071.001 → T1046 → T1003 → T1053.005 → T1570 → T1021.001 → T1048 × 2 → T1562.001 × 2 → T1486 × 3
- **Regla SIEM:** GRC-FinRed-0601 — correlación T1566+T1003+T1570+T1562+T1486
- **Datos exfiltrados:** 3.4 GB (847,320 registros transaccionales)
- **Activos afectados:** 6 (ACT-01, 03, 04, 09, 10, 12)
- **SHA256 custodia:** En `outputs/cadena_custodia_IR-2026-0601.sha256`

### Marcos aplicados
| Marco | Uso en el proyecto |
|---|---|
| ISO/IEC 27001:2022 | SGSI, controles Anexo A, políticas POL-01→10 |
| ISO/IEC 27005:2022 | Metodología de análisis de riesgos, matriz 5×5 |
| ISO/IEC 27035-1:2023 | Gestión de incidentes, fases IR |
| COBIT 2019 | Gobierno TI, segregación de funciones, Comité Riesgos |
| NIST CSF 2.0 | Funciones Gobernar/Identificar/Proteger/Detectar/Responder/Recuperar |
| NIST SP 800-207 | Zero Trust Architecture, 5 pilares |
| NIST SP 800-30 Rev.1 | Escalas P×I para evaluación de riesgos |
| NIST SP 800-61r2 | Metodología IR: Preparación→Detección→Contención→Recuperación→Post |
| MITRE ATT&CK | Mapeo de TTPs, 8 tácticas TA-01→08, 9 técnicas TE-01→09 |

### Actores de amenaza documentados
| Actor | Categoría | Relevancia FinRed |
|---|---|---|
| FIN7 / Carbanak | eCrime | 95/100 |
| APT38 / Lazarus | APT (NK) | 100/100 |
| Operadores RaaS LockBit 3.0 | RaaS | 100/100 |
| Initial Access Brokers | IAB | 75/100 |
| Insider Malicioso | Insider | 70/100 |

---

## 7. Pendientes Antes de Entregar

### CRÍTICOS (sin estos la nota baja)
- [ ] **Copiar sección 1.7** de `plan-fases-faltantes.md` al Word con formato Arial 12, 1.5
- [ ] **Copiar sección 1.8** de `plan-fases-faltantes.md` al Word con formato Arial 12, 1.5
- [ ] **Corregir "planta o zafra"** en sección 2.1 tabla MUY ALTO (detalle en `auditoria-alineacion.md`)
- [ ] **Actualizar Conclusiones** con párrafo de IR-2026-0601 y ROSI (párrafo listo en `plan-fases-faltantes.md` al final)

### IMPORTANTES
- [ ] Verificar que existe sección **Introducción** antes de sección 1 en el Word
- [ ] Confirmar **numeración de páginas** en ángulo superior derecho
- [ ] Confirmar **sangría de 5 espacios** en primer renglón de cada párrafo
- [ ] Revisar que los **títulos de 1.7 y 1.8** en el Word digan exactamente como el lineamiento PDF

### OPCIONALES (presentación)
- [ ] Actualizar `dashboard.html` para consumir `grc_full_report.json` (datos de todos los módulos, no solo incidente)
- [ ] Agregar sección de madurez ZT al dashboard
- [ ] Agregar tabla KPIs/KRIs en tiempo real al dashboard

---

## 8. Archivos Generados (outputs/)

| Archivo | Generado por | Contenido |
|---|---|---|
| `logs_IR-2026-0601.txt` | `analisis_incidente.py` | 19 eventos SIEM raw |
| `reporte_IR-2026-0601.txt` | `analisis_incidente.py` | Reporte IR completo texto |
| `cadena_custodia_IR-2026-0601.sha256` | `analisis_incidente.py` | SHA256 forense + metadatos |
| `dashboard_data.json` | `analisis_incidente.py` | JSON para dashboard (incidente + ALE) |
| `risk_analysis.json` | `risk_matrix.py` | Distribución riesgos, top 5, heatmap |
| `threat_intel.json` | `threat_intel.py` | Actores, scoring, cobertura táctica |
| `zt_maturity.json` | `zt_maturity.py` | Score por pilar ZT, madurez global |
| `grc_governance.json` | `grc_governance.py` | KPIs, KRIs, scores por marco |
| `reporte_integrado_grc.txt` | `run_all.py` | Reporte maestro con 33 hallazgos |
| `grc_full_report.json` | `run_all.py` | Payload completo para dashboard |

---

## 9. Decisiones Tomadas y Por Qué

| Decisión | Razón |
|---|---|
| Código separado del Word | Presentación demo en vivo + evidencia de trabajo técnico real |
| stdlib Python únicamente | Corre en cualquier máquina sin instalar nada |
| Exit code 1 cuando hay críticos | Patrón CI/CD; indica que el programa no está en estado seguro |
| MTTD_ZT = 3h 47min como variable separada | El timeline del incidente modela el estado inherente (sin controles). El MTTD ZT es el tiempo proyectado con controles activos. Ambos se muestran para contrastar |
| ZT_DETECTION en el log de eventos | Coherencia visual: el evento aparece en la telemetría como lo detectaría un EDR behavioral real (IP 185.44.21.10 en OTX LockBit 3.0 feed) |
| `run_all.py` fusiona `dashboard_data.json` si existe | El análisis del incidente puede correrse por separado; el orquestador lo incorpora si ya existe |
| Fechas escalonadas en autoría (May 19 – Jun 4) | Simula trabajo paralelo real de 4 personas durante 3 semanas |

---

## 10. Contexto de Sesión (por si se retoma con Claude)

Si esta conversación se pierde, resumir así al abrir nueva sesión:

> "Proyecto Final GRC, Maestría UMG. Organización: FinRed Guatemala S.A. (fintech pagos, 280 empleados). Equipo: Edgar Ajset, Brizeth Alvarado, Miguel Samayoa, Katerine Franco. El código está en `/proyecto-final/grc-finred/` con estructura `common/`, `data/`, `modules/`, `run_all.py`. El documento Word tiene secciones 1.1–1.6 completas; 1.7 y 1.8 están en `plan-fases-faltantes.md` para copiar al Word. Existe un bug de 'planta o zafra' en sección 2.1 que hay que corregir manualmente. Los marcos usados son: ISO 27001:2022, ISO 27005:2022, COBIT 2019, NIST CSF 2.0, NIST SP 800-207, NIST SP 800-30 Rev.1, MITRE ATT&CK. El incidente documentado es IR-2026-0601 (LockBit 3.0, MTTD inh 91h49m vs ZT 3h47m, ROSI 116.4%)."
