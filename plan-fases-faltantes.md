# Plan: Contenido Completo Secciones 1.7 y 1.8
**Proyecto:** GRC FinRed Guatemala, S.A.  
**Base:** Prácticas del curso (semanas 1, 5, 7) + Lineamiento PDF final  
**Uso:** Copiar/adaptar directamente al ProyectoFinalGRC.docx

---

## Calibración del catedrático (basada en las prácticas del curso)

El catedrático espera estructura ejecutable y medible. No acepta narrativa vaga:

| Criterio | NO aceptable | SÍ esperado |
|---|---|---|
| Incidente | "Hubo un ataque de ransomware" | "IR-2026-0601: Ransomware LockBit, P1-CRÍTICO, MTTD 4h, MTTR 72h, costo USD 462,000" |
| Costo | "pérdidas significativas" | "USD 462,000 = Q 3,603,600 (operativo + forensia + regulatorio)" |
| Riesgo | "riesgo alto" | "Inherente 25/25 → Residual 5/25 = -80%" |
| Fórmula | "P×I" mencionado | Tabla completa P(1-5) × I(1-5) = Score; Control efectividad %; Residual = Score × (1-efectividad) |

El catedrático **mapea MITRE con códigos T-específicos**, no solo nombres. Usa IDs de incidentes (IR-YYYY-XXXX). Requiere cadena de custodia forense (SHA256). Exige MTTD y MTTR con valores específicos contra targets.

---

---

# SECCIÓN 7. SIMULACIÓN DE INCIDENTE DE SEGURIDAD
*(Contenido listo para el Word — adaptar formato Arial 12, 1.5)*

---

## 7.1 Escenario: Operación "FinRed-0601" — Ransomware de Triple Extorsión

### 7.1.1 Descripción del escenario

FinRed Guatemala, S.A. sufre un ataque de ransomware ejecutado por un operador del grupo afiliado a FIN7, utilizando la variante LockBit 3.0. El ataque sigue el patrón de acceso inicial mediante spearphishing, movimiento lateral sobre la red corporativa, deshabilitación de defensas, cifrado del core transaccional y exfiltración previa para triple extorsión. Este escenario fue seleccionado porque materializa la cadena de ataque documentada en la sección 3 del presente programa, con involucramiento directo de los activos ACT-01, ACT-03, ACT-04 y ACT-12, y porque representa el vector de mayor impacto económico identificado en la evaluación de riesgos (SLE: Q 3,603,600).

El escenario se construye como simulación tabletop documentada, articulada con los controles Zero Trust definidos en la sección 4, los indicadores KPI/KRI de la sección 5, y el plan de respuesta a incidentes definido en POL-09.

**Identificación del incidente:**

| Campo | Valor |
|---|---|
| ID del Incidente | IR-2026-0601 |
| Tipo | Ransomware (triple extorsión) |
| Familia de malware | LockBit 3.0 |
| Severidad | P1 — CRÍTICO |
| Vector inicial | Spearphishing con adjunto malicioso (TE-01 / TA-01) |
| Activos afectados | ACT-01, ACT-03, ACT-04, ACT-09, ACT-10, ACT-12 |
| Riesgos materializados | RIE-03, RIE-08, RIE-12, RIE-25, RIE-28, RIE-32, RIE-36 |
| MTTD (estado inherente) | 96 horas (4 días) |
| MTTD (con controles ZT) | 3 horas 47 minutos |
| MTTR (con controles ZT) | 71 horas (recuperación parcial) |
| Impacto económico estimado | USD 462,000 / Q 3,603,600 |

---

### 7.1.2 Cadena de ataque — Kill Chain con MITRE ATT&CK

La secuencia de ataque se reconstruye utilizando el framework MITRE ATT&CK Enterprise, con trazabilidad directa a los escenarios de riesgo documentados en la sección 2.

**Tabla de kill chain — IR-2026-0601:**

| Fase | Táctica ATT&CK | ID Técnica | Nombre Técnica | Activo | RIE | Timestamp simulado |
|---|---|---|---|---|---|---|
| 1 — Acceso inicial | TA-01 Initial Access | T1566.001 | Phishing: Spearphishing Attachment | ACT-10 | RIE-28 | Día 1 — 08:14 |
| 2 — Ejecución | TA-02 Execution | T1059.001 | Command and Scripting: PowerShell | ACT-10 | RIE-29 | Día 1 — 08:15 |
| 3 — Persistencia | TA-03 Persistence | T1078 | Valid Accounts | ACT-09 | RIE-25 | Día 1 — 09:30 |
| 4 — Acceso a credenciales | TA-05 Credential Access | T1003 | OS Credential Dumping | ACT-02 | RIE-04 | Día 2 — 11:00 |
| 5 — Movimiento lateral | TA-06 Lateral Movement | T1570 | Lateral Tool Transfer | ACT-03 | RIE-08 | Día 2 — 14:22 |
| 6 — Exfiltración previa | TA-07 Exfiltration | T1048 | Exfiltration Over Web Service | ACT-04 | RIE-11 | Día 3 — 02:15 |
| 7 — Evasión de defensas | TA-04 Defense Evasion | T1562.001 | Impair Defenses: Disable/Modify Tools | ACT-11 | RIE-32 | Día 4 — 03:40 |
| 8 — Impacto | TA-08 Impact | T1486 | Data Encrypted for Impact | ACT-01, ACT-03, ACT-04, ACT-12 | RIE-03, RIE-09, RIE-12, RIE-36 | Día 4 — 04:01 |

**Correlación Kill Chain — Regla GRC-FinRed-0601:**

```
REGLA: GRC-FinRed-0601 — Kill Chain Ransomware Completo
CONDICIÓN: T1566.001 + T1003 + T1570 + T1486 correlacionados sobre mismos activos en ventana 96h
SEVERIDAD: P1 — CRÍTICO
ACCIÓN AUTOMÁTICA: Aislar segmento ACT-10 → revocar sesiones IAM → alertar CISO → ticket IR-2026-0601
MAPEADO A: NIST CSF RS.RP-1 / ISO/IEC 27035-1:2023 / COBIT DSS02
```

---

### 7.1.3 Detección

**Contexto pre-detección (Días 1–3, estado inherente sin controles maduros):**

La ausencia de sandbox de adjuntos en el correo corporativo permite la ejecución del dropper sin detección. La falta de microsegmentación entre la red corporativa (ACT-10) y el portal de soporte (ACT-09) hace que el movimiento lateral no genere alerta. Las configuraciones de exclusión excesiva en los agentes EDR (RIE-32) suprimen las alertas de ejecución de scripting nativo.

**Evento de detección — Día 4, 04:01:**

La detección ocurre cuando el SOC recibe correlación de tres alertas simultáneas sobre el SIEM centralizado (ACT-08):

**Registro de eventos SIEM — IR-2026-0601 (formato log):**

```
2026-06-15 03:40:12 | DEFENSE_EVASION | host=prod-srv-03 | agent=EDR_v4.2 | event=AGENT_DISABLED | user=svc_backup | T1562.001
2026-06-15 03:41:05 | DEFENSE_EVASION | host=prod-srv-01 | agent=EDR_v4.2 | event=AGENT_DISABLED | user=svc_backup | T1562.001
2026-06-15 04:01:44 | IMPACT          | host=db-transac-01 | process=lockbit3.exe | event=DATA_ENCRYPTED | targets=/data/transac/*.db | T1486
2026-06-15 04:02:11 | IMPACT          | host=auth-srv-01   | process=lockbit3.exe | event=DATA_ENCRYPTED | targets=/etc/app/*.conf | T1486
2026-06-15 04:03:30 | IMPACT          | host=backup-vault   | process=lockbit3.exe | event=DATA_ENCRYPTED | targets=/backup/*.tar.gz | T1486
2026-06-15 04:03:45 | KRI_THRESHOLD   | KRI=EDR_DISABLED | valor=2 | umbral=0 | ALERTA_CRÍTICA → CISO
2026-06-15 04:04:00 | KRI_THRESHOLD   | KRI=BACKUP_ACCESS_OOW | valor=1 | umbral=0 | ALERTA_CRÍTICA → JefeInfra
2026-06-15 04:04:15 | KILL_CHAIN_RULE | ID=GRC-FinRed-0601 | correlacion=T1566+T1003+T1570+T1486 | SEVERIDAD=P1 | ESCALADO_CISO
```

**Cadena de custodia forense:**

```
ARCHIVO: consolidated_IR-2026-0601_20260615.log
HASH SHA256: 3f7a9b2d4e6c1a8f5d2e9c7b4a3f6d8e2c1b9a7f4d3e6b8c2a1f9d7e4c3b2a1
GENERADO: 2026-06-15 04:05:00 UTC por SOC Analyst (Sistema automatizado)
CUSTODIO: Coordinador del SOC
PROPÓSITO: Evidencia forense IR-2026-0601 — integridad de logs de detección
```

**Señales de alerta activadas — Día 4, 04:01–04:05:**

| ID Alerta | KRI/KPI activado | Valor detectado | Umbral | Responsable notificado |
|---|---|---|---|---|
| ALERTA-001 | KRI: Desactivación de agentes EDR | 2 agentes desactivados | Cualquiera > 0 | Coordinador del SOC |
| ALERTA-002 | KRI: Accesos a respaldos fuera de ventana | 1 acceso 04:03 | Solo 22:00–02:00 | Jefe de Infraestructura |
| ALERTA-003 | KPI: MTTD | 3h 47min | < 24h — cumplido | CISO |
| CORRELACIÓN | GRC-FinRed-0601 | Kill chain completo | Disparado | Comité de Riesgos |

---

### 7.1.4 Respuesta

La respuesta se activa bajo el ciclo NIST SP 800-61r2 (Preparación → Detección → Contención → Recuperación → Post-incidente) articulado con el proceso POL-09 y el rol del CISO definido en la sección 5.3.

**FASE 1 — PREPARACIÓN (pre-incidente):**

| Elemento pre-posicionado | Estado |
|---|---|
| Runbook IR-RAN-01 (Ransomware) disponible en plataforma GRC | Activo |
| Retainer de respuesta a incidentes (empresa forense externa) contratado | Vigente |
| Respaldos Object Lock (WORM) en vault aislado | Verificado último ciclo nocturno 2026-06-14 22:00 |
| Contactos de notificación SIB predefinidos | Disponibles |
| Plantilla de notificación a clientes redactada | Lista para envío |

**FASE 2 — CONTENCIÓN (Día 4, 04:05–08:00):**

| Hora | Acción de contención | Ejecutor | Control ZT aplicado |
|---|---|---|---|
| 04:05 | Clasificación P1-CRÍTICO, activación Comité de Riesgos extraordinario | CISO | POL-09 — Runbook IR-RAN-01 |
| 04:10 | Aislamiento de red: segmento ACT-10 desconectado de producción | Jefe Infraestructura | Microsegmentación / ZTNA — POL-05 |
| 04:15 | Revocación masiva de todas las sesiones activas en IAM | Administrador IAM | ZT: revocación forzosa de tokens |
| 04:20 | Bloqueo perimetral de IPs C2 identificadas en feed CTI (OTX/MISP) | SOC Analyst | Integración CTI — Sección 3.1 |
| 04:30 | Modo lectura-solamente en bases de datos no cifradas (ACT-04 parcial) | DBA | Control de acceso mínimo privilegio |
| 04:45 | Notificación formal a Superintendencia de Bancos (SIB) — obligación regulatoria | CISO + Dirección Cumplimiento | POL-10 — Obligación de reporte |
| 05:00 | Activación de canales de comunicación alternos (sin infraestructura comprometida) | Dirección General | Plan de continuidad |
| 07:30 | Preservación de memoria RAM y logs previo apagado de sistemas afectados | Analista Forense externo | Cadena de custodia / POL-09 |

**FASE 3 — INVESTIGACIÓN FORENSE (Días 4–5, 08:00–48:00):**

| Actividad forense | Resultado |
|---|---|
| Identificación del paciente cero | Endpoint corporativo del analista de soporte (ACT-09) |
| Vector de entrada confirmado | Adjunto malicioso en correo de phishing recibido Día 1, 08:14 |
| Cuentas comprometidas | svc_backup, admin-portal-01, api_integra_03 |
| IoCs extraídos | Hash dropper: 7c4e9a1b3f2d6e8c, IPs C2: 185.44.21.10, 91.220.163.47 |
| Alcance del cifrado | ACT-01 (100%), ACT-03 (100%), ACT-04 (78%), ACT-12 (45%) |
| Exfiltración confirmada | 3.4 GB de datos transaccionales (Día 3, 02:15 UTC) |
| IoCs publicados en MISP | Disponibles para otras entidades del sector (TLP:GREEN) |

---

### 7.1.5 Recuperación

**Verificación de respaldos (Día 5, 08:00):**

Los respaldos almacenados con Object Lock/WORM (control implementado para RIE-36) no fueron cifrados. El módulo de ransomware localizó el vault pero no pudo sobrescribir los archivos por la política de inmutabilidad. Este control fue determinante para la recuperación operativa sin pago de rescate.

**Tiempos de recuperación — RPO y RTO:**

| Sistema | Activo | Estado post-cifrado | Fuente recuperación | RPO logrado | RTO logrado |
|---|---|---|---|---|---|
| Base de datos transaccional | ACT-04 | 78% cifrado | Respaldo inmutable nocturno (2026-06-14 22:00) | 6 horas de datos | 9 horas |
| Servidores de autenticación | ACT-01 | 100% cifrado | Snapshot cloud con rotación horaria | 1 hora de datos | 4 horas |
| Servidores de aplicación de pagos | ACT-03 | 100% cifrado | Imagen de contenedor inmutable (CI/CD) | < 1 hora | 6 horas |
| Sistema de respaldos | ACT-12 | 45% cifrado | Copia offsite en custodio externo | N/A | 18 horas |
| **Retorno operativo parcial** | | | | | **Día 5, 17:00** |
| **Retorno operativo completo** | | | | | **Día 7, 10:00** |

**Acciones de erradicación (Día 5–6):**

- Reimagen completa de todos los sistemas afectados desde línea base limpia
- Rotación de todas las credenciales (cuentas comprometidas, llaves API, tokens de firma)
- Reinstalación y reconfiguración de agentes EDR con hardening de exclusiones
- Validación de integridad transaccional: reconciliación de los últimos 6 horas de datos faltantes con logs de APIs externas (bancos integrados)
- Comunicación formal a clientes, comercios afiliados y SIB sobre restauración completa

---

### 7.1.6 Lecciones Aprendidas

| # | Lección identificada | Causa raíz en estado inherente | Control Zero Trust que la mitiga | Acción correctiva prioritaria |
|---|---|---|---|---|
| LL-01 | Sin sandbox de adjuntos, el dropper pasó el filtro de correo sin alerta | Ausencia de inspección avanzada de contenido | EDR/XDR con protección de correo; formación anti-phishing (POL-09) | Implementar sandbox de análisis de adjuntos en gateway de correo |
| LL-02 | Falta de microsegmentación convirtió un endpoint de soporte en puente al core transaccional | Red plana sin aislamiento lógico | mTLS entre segmentos; ZTNA para acceso a producción (POL-05, Sección 4.4) | Prioridad 1: microsegmentación entre ACT-09 y ACT-03 |
| LL-03 | La cuenta de servicio svc_backup tenía permisos de escritura en sistemas de producción y fue el vector de deshabilitación de EDR | Ausencia de Just-in-Time; privilegios permanentes excesivos | PAM + accesos Just-in-Time; revisión de cuentas de servicio (POL-03, Sección 4.2) | Eliminar privilegios permanentes en cuentas de servicio; implementar PAM |
| LL-04 | El sistema de respaldos Object Lock sobrevivió al cifrado; sin este control la recuperación requeriría pago de rescate o pérdida total de datos | Control implementado preventivamente para RIE-36 | Object Lock / WORM en vault de respaldos (POL-08) | Extender cobertura WORM al 100% de los respaldos (actualmente 45% afectado) |
| LL-05 | MTTD de 96 horas en estado inherente vs. 3h 47min con controles ZT — diferencia de 25 veces | Sin correlación de eventos en SIEM ni reglas de Kill Chain | Reglas SIEM alineadas a T1562.001, T1570, T1486; SOC 24/7 (POL-09, Sección 4.5) | Activar regla GRC-FinRed-0601 Kill Chain en SIEM |
| LL-06 | La notificación a la SIB debe ejecutarse dentro de los primeros 30 minutos desde la clasificación P1; el proceso actual no tenía un runbook con este requerimiento explícito | Runbook de IR sin checklist de obligaciones regulatorias | Runbook actualizado con checklist de notificación SIB en paso 3 de contención (POL-10) | Actualizar Runbook IR-RAN-01 con notificación regulatoria como step obligatorio |
| LL-07 | Los 3.4 GB exfiltrados el Día 3 no fueron detectados en tiempo real | Sin alertas DLP sobre consultas masivas a ACT-04 | Alertas DLP sobre queries masivos a base de datos transaccional (KRI: "Consultas masivas a BD") | Activar regla DLP sobre ACT-04 con umbral de volumen definido |

**Indicadores de desempeño — IR-2026-0601:**

| Indicador | Meta (Sección 5.5) | Resultado obtenido | Estado |
|---|---|---|---|
| MTTD | < 24 horas | 3h 47min | CUMPLE |
| MTTR | < 8 horas (contención) | 4 horas (contención parcial) | CUMPLE |
| Retorno operativo completo | < 72 horas | 71 horas | CUMPLE (por 1h) |
| Notificación SIB | < 2 horas desde clasificación P1 | 40 minutos | CUMPLE |
| Preservación de evidencia (SHA256) | 100% logs hash-verificados | 100% | CUMPLE |
| Riesgo residual post-incidente | Mantener nivel global BAJO | Recalculado: BAJO (8 escenarios ascendieron temporalmente, retorno proyectado 30 días) | EN PROCESO |

---

---

# SECCIÓN 8. ANÁLISIS DE COSTO–BENEFICIO

---

## 8.1 Metodología de Análisis Económico

El análisis de costo–beneficio del programa de controles de FinRed Guatemala se estructura mediante la metodología cuantitativa de Pérdida Anual Esperada (ALE — Annual Loss Expectancy), complementada con el cálculo del Retorno sobre Inversión en Seguridad (ROSI — Return on Security Investment). Este enfoque es consistente con el modelo de evaluación de impacto financiero descrito en el NIST SP 800-30 Rev. 1 y con los principios de cuantificación de riesgo del estándar ISO/IEC 27005:2022 (International Organization for Standardization, 2022b; National Institute of Standards and Technology, 2012).

Las fórmulas aplicadas son:

```
SLE  (Single Loss Expectancy)  = Impacto financiero de un único evento de materialización
ARO  (Annual Rate of Occurrence) = Frecuencia anual estimada del evento (basada en probabilidad de la matriz)
ALE  (Annual Loss Expectancy)  = SLE × ARO
ROSI (Return on Security Investment) = (ALE_antes − ALE_después − Costo_controles) / Costo_controles
Riesgo Residual = Score_inherente × (1 − Efectividad_control)
```

Los valores de probabilidad e impacto se derivan directamente de la matriz de riesgos documentada en la sección 2 del presente programa. Los costos de controles son estimaciones de mercado para soluciones equivalentes a las propuestas en la arquitectura Zero Trust (sección 4), con precios de referencia para el mercado guatemalteco.

---

## 8.2 Estimación de Impacto Económico de Riesgos

### 8.2.1 Conversión de escala de impacto a valores financieros (contexto FinRed)

La escala de impacto definida en la metodología (sección 2.1) se traduce a valores financieros concretos para FinRed Guatemala:

| Nivel | Score | Definición operativa en FinRed | Rango Q | Rango USD |
|---|---|---|---|---|
| INSIGNIFICANTE | 1 | Afectación imperceptible, recuperación < 1h | < Q 40,000 | < USD 5,100 |
| MENOR | 2 | Retraso operativo menor, recuperación < 4h | Q 40k–Q 200k | USD 5,100–USD 25,600 |
| MODERADO | 3 | Afectación parcial, recuperación 4–8h | Q 200k–Q 800k | USD 25,600–USD 102,500 |
| MAYOR | 4 | Interrupción de línea crítica, 8–24h | Q 800k–Q 4M | USD 102,500–USD 512,800 |
| CATASTRÓFICO | 5 | Paro total de plataforma transaccional > 24h; multas SIB; pérdida > Q 4M | > Q 4M | > USD 512,800 |

Tipo de cambio de referencia: USD 1 = Q 7.80 (junio 2026).  
Costo por hora de inactividad transaccional estimado: Q 200,000 / hora (basado en volumen promedio de transacciones de FinRed y tasa de ingreso por comisión).

### 8.2.2 Análisis ALE por vector de amenaza principal

**Vector 1: Ransomware — IR-2026-0601 como caso base**

| Componente del impacto | Costo (Q) | Costo (USD) | Base de cálculo |
|---|---|---|---|
| Pérdida de ingresos (71 horas de inactividad total) | Q 1,420,000 | USD 182,051 | Q 200k/hora × 7.1 horas críticas por día × 2 días |
| Respuesta a incidentes (retainer forense externo + SOC) | Q 390,000 | USD 50,000 | Retainer de respuesta IR en mercado regional |
| Restauración de sistemas y validación | Q 234,000 | USD 30,000 | Horas técnicas + licencias de emergencia |
| Multas regulatorias SIB (estimación conservadora) | Q 390,000 | USD 50,000 | Referencia: sanciones por interrupción de servicio sector financiero Guatemala |
| Daño reputacional (estimado 4% churn de comercios afiliados en T+1) | Q 780,000 | USD 100,000 | 4% × base de comercios × ingreso promedio anual por comercio |
| Pérdidas por datos exfiltrados (notificación + monitoreo de identidad) | Q 390,000 | USD 50,000 | 3.4 GB ≈ 43,600 registros × costo de notificación regulatoria |
| **SLE total — Ransomware** | **Q 3,604,000** | **USD 462,051** | |
| ARO sin controles (Probabilidad PROBABLE = nivel 4 → 0.30/año) | 0.30 | 0.30 | Conversión NIST SP 800-30 Tabla D-1 |
| **ALE — Ransomware (sin controles)** | **Q 1,081,200/año** | **USD 138,615/año** | |

**Vector 2: Exfiltración de datos transaccionales — RIE-11, RIE-19**

| Componente del impacto | Costo (Q) | Costo (USD) |
|---|---|---|
| Costos de notificación a usuarios afectados (Ley Protección Datos Guatemala) | Q 156,000 | USD 20,000 |
| Multas regulatorias SIB por exposición de datos financieros | Q 546,000 | USD 70,000 |
| Pérdida de clientes directos (estimado 8% churn) | Q 936,000 | USD 120,000 |
| Costos forenses y remediación técnica de APIs | Q 234,000 | USD 30,000 |
| Daño reputacional en mercado fintech Guatemala | Q 312,000 | USD 40,000 |
| **SLE total — Exfiltración API** | **Q 2,184,000** | **USD 280,000** | |
| ARO sin controles (PROBABLE = 0.40 para RIE-19 y RIE-21) | 0.40 | 0.40 | |
| **ALE — Exfiltración API (sin controles)** | **Q 873,600/año** | **USD 112,000/año** | |

**Vector 3: Phishing / Compromiso de personal de soporte — RIE-25, RIE-28**

| Componente del impacto | Costo (Q) | Costo (USD) |
|---|---|---|
| Fraude en cuentas manipuladas (reversa de transacciones) | Q 234,000 | USD 30,000 |
| Investigación interna y forensia básica | Q 78,000 | USD 10,000 |
| Gestión de crisis comunicacional | Q 117,000 | USD 15,000 |
| **SLE total — Phishing/Soporte** | **Q 429,000** | **USD 55,000** | |
| ARO sin controles (CASI SEGURO = 0.80 para RIE-28) | 0.80 | 0.80 | |
| **ALE — Phishing/Soporte (sin controles)** | **Q 343,200/año** | **USD 44,000/año** | |

**Vector 4: Insider Threat / Abuso de credenciales — RIE-06, RIE-10**

| Componente del impacto | Costo (Q) | Costo (USD) |
|---|---|---|
| Alteración de saldos o transacciones (estimación 0.1% del volumen mensual) | Q 468,000 | USD 60,000 |
| Investigación forense interna + externa | Q 156,000 | USD 20,000 |
| Consecuencias regulatorias y legales | Q 312,000 | USD 40,000 |
| **SLE total — Insider Threat** | **Q 936,000** | **USD 120,000** | |
| ARO sin controles (POSIBLE = 0.20 para RIE-06) | 0.20 | 0.20 | |
| **ALE — Insider Threat (sin controles)** | **Q 187,200/año** | **USD 24,000/año** | |

**Resumen de exposición económica anual — Estado inherente (sin controles):**

| Vector | ALE anual (Q) | ALE anual (USD) |
|---|---|---|
| Ransomware | Q 1,081,200 | USD 138,615 |
| Exfiltración API | Q 873,600 | USD 112,000 |
| Phishing/Soporte | Q 343,200 | USD 44,000 |
| Insider Threat | Q 187,200 | USD 24,000 |
| **TOTAL ALE inherente** | **Q 2,485,200/año** | **USD 318,615/año** |

---

## 8.3 Justificación de Inversión en Controles

Los controles propuestos se agrupan por dominio Zero Trust, con estimación de costo anual (SaaS/licencias recurrentes) y efectividad de reducción de riesgo sobre los vectores que tratan:

### Plan de tratamiento — Costo vs. efectividad vs. vectores cubiertos

| ID | Control | Grupo ZT | Costo anual (Q) | Costo anual (USD) | Efectividad estimada | Vectores cubiertos |
|---|---|---|---|---|---|---|
| CTR-01 | Plataforma IAM centralizada (Azure AD P2 / equivalente) | Identidad | Q 140,400 | USD 18,000 | 80% sobre TE-03, RIE-04, RIE-06 | Ransomware, Insider, Phishing |
| CTR-02 | PAM — Privileged Access Management (CyberArk / BeyondTrust básico) | Identidad | Q 93,600 | USD 12,000 | 75% sobre RIE-06, RIE-10, RIE-26 | Insider, Ransomware |
| CTR-03 | MFA resistente a phishing (FIDO2 — llaves hardware para admins) | Identidad | Q 46,800 | USD 6,000 | 85% sobre RIE-04, RIE-14, RIE-25 | Phishing, Ransomware |
| CTR-04 | ZTNA (Zscaler / Cloudflare Access) | Red | Q 109,200 | USD 14,000 | 70% sobre RIE-04, RIE-05, RIE-17, RIE-27 | Ransomware, APT |
| CTR-05 | Microsegmentación mTLS entre servicios (service mesh) | Red | Q 62,400 | USD 8,000 | 85% sobre RIE-08, RIE-18, RIE-27, RIE-30 | Ransomware, APT |
| CTR-06 | SIEM cloud (Microsoft Sentinel básico) | Detección | Q 156,000 | USD 20,000 | 75% reducción MTTD | Todos los vectores |
| CTR-07 | EDR/XDR en todos los endpoints corporativos | Detección | Q 70,200 | USD 9,000 | 70% sobre RIE-28, RIE-29, RIE-32 | Ransomware, Phishing |
| CTR-08 | CTI — Membresía FS-ISAC + OTX automatizado | Detección | Q 39,000 | USD 5,000 | 60% reducción tiempo de respuesta | Todos los vectores |
| CTR-09 | Object Lock / WORM en vault de respaldos | Datos | Q 46,800 | USD 6,000 | 95% sobre RIE-36 (recuperación sin rescate) | Ransomware |
| CTR-10 | Cifrado TDE AES-256 + alertas DLP | Datos | Q 62,400 | USD 8,000 | 80% sobre RIE-11, RIE-39 | Exfiltración, APT |
| CTR-11 | API Gateway con rate limiting + WAF actualizado | Datos/App | Q 78,000 | USD 10,000 | 85% sobre RIE-19, RIE-21 | Exfiltración API, APT |
| **TOTAL inversión anual en controles** | | | **Q 904,800** | **USD 116,000** | | |

---

## 8.4 Comparación Costo vs. Mitigación

### 8.4.1 ALE después de implementar controles (riesgo residual objetivo — Sección 2.4)

La reducción del ALE se calcula con la fórmula:

```
ALE_residual = SLE × ARO_residual
ARO_residual = ARO_inherente × (1 − Efectividad_control_promedio)
```

| Vector | ALE inherente (Q) | Controles aplicados | Efectividad promedio | ALE residual (Q) | Reducción |
|---|---|---|---|---|---|
| Ransomware | Q 1,081,200 | CTR-01+02+03+05+06+07+09 | 83% | Q 183,804 | -83% |
| Exfiltración API | Q 873,600 | CTR-04+06+08+10+11 | 80% | Q 174,720 | -80% |
| Phishing/Soporte | Q 343,200 | CTR-01+03+06+07 | 70% | Q 102,960 | -70% |
| Insider Threat | Q 187,200 | CTR-01+02+06 | 65% | Q 65,520 | -65% |
| **TOTAL ALE residual** | | | | **Q 527,004/año** | **-79%** |

### 8.4.2 Tabla de evaluación cuantitativa por riesgo crítico

| ID Riesgo | Activo | Score inherente (P×I) | Efectividad control | Score residual | Costo control anual (Q) | ALE reducido (Q/año) |
|---|---|---|---|---|---|---|
| RIE-13 | ACT-05 App móvil (clonación) | 20/25 (PROBABLE×CATASTRÓFICO) | 20% (solo detectivo) | 16/25 (MUY ALTO residual aceptado) | Q 31,200 | Q 120,000 |
| RIE-11 | ACT-04 Exfiltración BD | 20/25 (PROBABLE×CATASTRÓFICO) | 80% (DLP + cifrado) | 4/25 (MUY BAJO) | Q 62,400 | Q 698,880 |
| RIE-28 | ACT-10 Phishing red corp. | 25/25 (CASI SEGURO×CATASTRÓFICO) | 70% (EDR+MFA+SIEM) | 7.5/25 (BAJO) | Q 156,000 | Q 240,240 |
| RIE-36 | ACT-12 Cifrado de respaldos | 15/25 (PROBABLE×MAYOR) | 95% (Object Lock) | 0.75/25 (MUY BAJO) | Q 46,800 | Q 486,540 |
| RIE-06 | ACT-02 Insider/IAM | 12/25 (POSIBLE×MAYOR) | 65% (PAM+JIT) | 4.2/25 (BAJO residual MEDIO aceptado) | Q 93,600 | Q 121,680 |

### 8.4.3 Cuadro comparativo final — Inversión vs. retorno

| Concepto | Valor anual (Q) | Valor anual (USD) |
|---|---|---|
| ALE total estado inherente (sin controles) | Q 2,485,200 | USD 318,615 |
| ALE total estado residual (con controles) | Q 527,004 | USD 67,565 |
| **Reducción de riesgo económico anual** | **Q 1,958,196** | **USD 251,050** |
| Inversión total en controles (año 1) | Q 904,800 | USD 116,000 |
| **Beneficio neto año 1** | **Q 1,053,396** | **USD 135,050** |
| **ROSI año 1** | **(Q 1,958,196 − Q 904,800) / Q 904,800 = 116.4%** | |
| **Periodo de recuperación (payback)** | **< 6 meses** | |

### 8.4.4 Análisis de costo por control con mayor ROI individual

| Control | Inversión anual (Q) | ALE mitigado (Q/año) | ROI individual |
|---|---|---|---|
| CTR-09 Object Lock / WORM | Q 46,800 | Q 897,540 (RIE-36 evita pago de rescate) | 1,817% |
| CTR-11 API Gateway + WAF | Q 78,000 | Q 698,880 (RIE-11 exfiltración) | 796% |
| CTR-05 Microsegmentación mTLS | Q 62,400 | Q 540,000 (movimiento lateral bloqueado) | 765% |
| CTR-06 SIEM cloud | Q 156,000 | Q 480,000 (MTTD: 96h → 3h 47min, contención temprana) | 208% |
| CTR-03 MFA FIDO2 | Q 46,800 | Q 240,000 (phishing eliminado como vector de acceso admin) | 413% |

---

## 8.5 Interpretación y Decisión de Inversión

El análisis cuantitativo establece que el programa de controles propuesto tiene un **ROSI del 116.4%** en el primer año de operación y un **periodo de recuperación menor a 6 meses**. Esto significa que por cada quetzal invertido en controles, FinRed recupera Q 2.16 en riesgo mitigado. Desde la perspectiva del Comité de Riesgos y la Alta Dirección, el programa de controles no constituye un costo de cumplimiento, sino una inversión con retorno financiero positivo y verificable dentro del mismo ejercicio fiscal.

El control de mayor impacto individual con menor inversión es el Object Lock / WORM en los respaldos (CTR-09, Q 46,800/año), que elimina la capacidad del ransomware de destruir la única copia de recuperación — condición que convirtió el incidente IR-2026-0601 en recuperable sin pago de rescate. Sin este control, el rescate exigido (USD 2.5 millones en el escenario de triple extorsión) superaría en 21 veces el costo anual del control.

El análisis también identifica que el vector de exfiltración de APIs (RIE-11, RIE-19, RIE-21) representa la segunda mayor fuente de exposición económica (ALE: Q 873,600/año) y que su mitigación mediante CTR-11 (API Gateway + WAF, Q 78,000/año) tiene un ROI individual del 796%, siendo la inversión con mayor relación costo-beneficio después del control de respaldos.

Finalmente, se precisa que el escenario RIE-13 (clonación de aplicación móvil, riesgo residual MUY ALTO aceptado formalmente) no fue incluido en el cálculo de mitigación por ser su control de naturaleza exclusivamente detectiva. Esta decisión es consistente con la aceptación formal documentada en la sección 2.4, donde el Comité de Riesgos asume el riesgo residual con controles compensatorios de concientización al usuario final y validaciones del lado del servidor.

---

## Notas de redacción para el Word

**Citas que deben aparecer en estas secciones (ya en la bibliografía del proyecto):**
- National Institute of Standards and Technology (2012) — NIST SP 800-30 Rev. 1 → para metodología ALE
- International Organization for Standardization (2022b) — ISO/IEC 27005:2022 → para criterios de aceptación
- International Organization for Standardization (2023) — ISO/IEC 27035-1:2023 → para ciclo IR
- MITRE Corporation (2023) — ATT&CK Enterprise → para técnicas T1566.001, T1003, T1570, T1486, T1048, T1562.001

**No requieren nuevas referencias** — todas ya están en la sección 11 del documento.

**Actualizar Conclusiones (Sección 9):** Agregar al final del tercer párrafo:
> "La simulación del incidente IR-2026-0601 demostró que los controles Zero Trust implementados reducen el MTTD de 96 horas a 3 horas 47 minutos, y que el control de respaldos inmutables fue determinante para lograr la recuperación completa sin pago de rescate en menos de 72 horas. El análisis de costo–beneficio cuantifica un ROSI del 116.4% en el primer año, con un periodo de recuperación de la inversión menor a 6 meses, validando que el programa GRC constituye una inversión con retorno financiero positivo dentro del mismo ejercicio fiscal."
