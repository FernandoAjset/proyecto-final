# Auditoría de Alineación: ProyectoFinalGRC.docx vs Lineamientos PDF
**Fecha de revisión:** 2026-06-08  
**Evaluador:** Revisión interna pre-entrega  
**Documento auditado:** ProyectoFinalGRC.docx  
**Lineamiento base:** Proyecto Final – GRC.pdf (Universidad Mariano Gálvez, 2026)

---

## 1. Resumen Ejecutivo

El avance cubre **6 de 8 componentes** requeridos. Las secciones 1.1–1.6 están desarrolladas con profundidad, rigor técnico y citas APA 7 suficientes. Las secciones **1.7 y 1.8 son marcadores vacíos** (solo contienen el texto del enunciado del rubric). Existe **una desviación grave** que debe corregirse antes de la entrega.

| Componente | Estado | Riesgo académico |
|---|---|---|
| 1.1 Contexto Organizacional | ✅ Completo | Ninguno |
| 1.2 Identificación y Análisis de Riesgos | ✅ Completo | Ninguno |
| 1.3 Threat Intelligence | ✅ Completo | Ninguno |
| 1.4 Arquitectura Zero Trust | ✅ Completo | Ninguno |
| 1.5 Gobierno y Cumplimiento | ✅ Completo | Ninguno |
| 1.6 Marcos Internacionales | ✅ Completo | Ninguno |
| 1.7 Simulación de Incidente | ❌ Vacío | **Crítico** |
| 1.8 Análisis Costo–Beneficio | ❌ Vacío | **Crítico** |
| Mínimo 10 citas APA 7 | ✅ 25 referencias | Ninguno |
| Conclusiones y Recomendaciones | ✅ Completo | Menor* |
| Formato (Arial 12, 1.5, márgenes) | No verificable en .md | — |

*Las conclusiones dicen que "el programa se completó" pero 1.7 y 1.8 están vacíos. Corregir tras completar esas secciones.

---

## 2. Desviación Grave — Acción Requerida

### 2.1 Error de contexto: texto industrial en matriz de riesgo fintech

**Ubicación:** Sección 2.1 — tabla de clasificación de criticidad, fila MUY ALTO.

**Texto actual:**
> "Paro total de la **planta o zafra** por > 24h."

**Problema:** "Planta" y "zafra" son términos de contexto industrial/agroindustrial (manufactura, caña de azúcar). FinRed Guatemala es una **fintech de pagos digitales**. Este texto fue copiado de una plantilla MAGERIT para sector industrial sin adaptarlo. Un catedrático de Maestría en Seguridad Informática lo identificará inmediatamente y cuestionará la calidad del análisis de riesgos completo.

**Corrección propuesta:**
> "Interrupción total de la plataforma transaccional por > 24h; pérdida > Q4M o 5% del presupuesto anual; fatalidades o incapacidades permanentes no aplican en contexto fintech (N/A); revocación de licencia de operación, demandas penales o intervención de SIB."

**Prioridad: Corregir antes de cualquier otra cosa.**

---

## 3. Revisión Detallada por Sección

### 3.1 Contexto Organizacional (Sección 1)

**Cumplimiento:** Excelente.

| Requisito del lineamiento | Presente | Observación |
|---|---|---|
| Descripción de organización (real o ficticia) | ✅ | FinRed Guatemala, S.A. — fintech 280 colaboradores |
| Sector | ✅ | Tecnología financiera / pagos digitales |
| Activos críticos | ✅ | ACT-01 a ACT-13, con tabla estructurada |
| Infraestructura tecnológica | ✅ | Cloud IaaS/PaaS, APIs, app móvil, red corporativa |
| Procesos clave | ✅ | 10 procesos identificados con riesgo asociado |

No hay desviaciones.

---

### 3.2 Identificación y Análisis de Riesgos (Sección 2)

**Cumplimiento:** Excelente, con la advertencia del punto 2.1.

| Requisito del lineamiento | Presente | Observación |
|---|---|---|
| Ransomware | ✅ | Análisis profundo, cadena de ataque documentada |
| Phishing | ✅ | 3 rutas diferenciadas, incluyendo clonación app móvil |
| Insider Threat | ✅ | Vinculado a TE-03 y TA-05 |
| APTs | ✅ | FIN7, APT38/Lazarus documentados |
| Identificación de vulnerabilidades | ✅ | 39 escenarios RIE-01 a RIE-39 |
| Evaluación impacto y probabilidad | ✅ | Escala 5×5, justificación metodológica sólida |
| Matriz de riesgos | ✅ | Distribución inherente y residual |
| Referencia ISO/IEC 27005 | ✅ | ISO/IEC 27005:2022 citado correctamente |
| Referencia NIST RMF | ✅ | NIST SP 800-30 Rev. 1 citado correctamente |

**Punto para preparar si el catedrático pregunta:** La justificación de que RIE-13 (clonación app móvil) queda en riesgo residual MUY ALTO es sólida y está bien argumentada. No es un error; es una decisión metodológica correctamente documentada.

---

### 3.3 Threat Intelligence (Sección 3)

**Cumplimiento:** Excelente, supera el mínimo requerido.

| Requisito del lineamiento | Presente | Observación |
|---|---|---|
| Fuentes OSINT | ✅ | AlienVault OTX, MISP, CISA KEV |
| Fuentes comerciales | ✅ | Microsoft Defender TI, FS-ISAC |
| Análisis de amenazas relevantes | ✅ | FIN7, APT38, IABs, vectores LATAM |
| MITRE ATT&CK | ✅ | 8 tácticas (TA-01 a TA-08), 9 técnicas (TE-01 a TE-09) |

El lineamiento pedía MITRE ATT&CK como herramienta de mapeo. La sección lo implementa con trazabilidad directa hacia los escenarios de riesgo. Es uno de los puntos más sólidos del documento.

---

### 3.4 Arquitectura Zero Trust (Sección 4)

**Cumplimiento:** Excelente.

| Requisito del lineamiento | Presente | Observación |
|---|---|---|
| Zero Trust Architecture | ✅ | NIST SP 800-207, Policy Engine/Administrator/Enforcement |
| IAM | ✅ | Centralizado, roles, mínimo privilegio, cuentas de servicio |
| MFA | ✅ | Obligatorio accesos críticos, FIDO2 para administradores |
| Microsegmentación de red | ✅ | mTLS, ZTNA, segmentación por microsegmento |
| Monitoreo continuo | ✅ | SIEM, SOC, CTI integrado, casos de uso MITRE |

---

### 3.5 Gobierno y Cumplimiento (Sección 5)

**Cumplimiento:** Excelente, supera ampliamente el mínimo.

| Requisito del lineamiento | Presente | Observación |
|---|---|---|
| Políticas de seguridad | ✅ | POL-01 a POL-10, 10 políticas completas |
| CISO | ✅ | Funciones, competencias, relación con órganos de gobierno |
| Comité de riesgos | ✅ | Conformación, quórum, duración de cargos |
| KPIs | ✅ | 12 KPIs con meta, frecuencia y responsable |
| KRIs | ✅ | 10 KRIs con umbral de alerta |
| Auditoría y monitoreo | ✅ | Plan de auditoría, monitoreo continuo, gestión de hallazgos |

---

### 3.6 Marcos Internacionales (Sección 6)

**Cumplimiento:** Excelente. El lineamiento pedía mínimo 2; el documento integra 3.

| Marco requerido | Presente | Cómo está integrado |
|---|---|---|
| ISO/IEC 27001 | ✅ | SGSI, Anexo A, ciclo PDCA, ISO/IEC 27005 complementario |
| COBIT | ✅ | Gobierno TI, segregación de funciones, Comité de Riesgos |
| NIST Cybersecurity Framework | ✅ | CSF 2.0 funciones Gobernar/Identificar/Proteger/Detectar/Responder/Recuperar |

La tabla de integración de marcos al final de la sección está bien construida y responde directamente al criterio de evaluación.

---

### 3.7 Sección 1.7 — Simulación de Incidente

**Estado: AUSENTE.** Solo contiene el enunciado del rubric como placeholder. Sin contenido.

---

### 3.8 Sección 1.8 — Análisis Costo–Beneficio

**Estado: AUSENTE.** Solo contiene el enunciado del rubric como placeholder. Sin contenido.

---

## 4. Coherencia Interna del Documento

### 4.1 Contradicción en Conclusiones

**Problema menor:** Las Conclusiones (Sección 9) afirman que "el programa se completó" con todos sus elementos. Esto es inconsistente porque las secciones 7 y 8 están vacías al momento de esta auditoría.

**Acción:** Revisar y actualizar el párrafo de conclusiones tras completar 1.7 y 1.8 para que mencione la simulación y el análisis costo-beneficio como parte del programa completado.

### 4.2 Numeración vs. Lineamiento

El documento usa numeración secuencial (1, 2, 3... para las secciones principales) mientras el lineamiento las lista como subsecciones (1.1, 1.2...). Esto no es un problema; es una decisión de estructura de documento que no afecta el contenido evaluado.

### 4.3 Consistencia de Referencias

Las 25 referencias están en formato APA 7 y son fuentes reconocidas (NIST, ISO, ISACA, Mandiant, OWASP, etc.). Supera el mínimo de 10 requerido. No hay referencias huérfanas identificadas en la revisión.

---

## 5. Checklist Final para Entrega

| # | Ítem | Estado |
|---|---|---|
| 1 | Corregir "planta o zafra" → contexto fintech | ⚠️ Pendiente |
| 2 | Completar Sección 1.7 (Simulación de Incidente) | ❌ Pendiente |
| 3 | Completar Sección 1.8 (Análisis Costo–Beneficio) | ❌ Pendiente |
| 4 | Actualizar Conclusiones para mencionar 1.7 y 1.8 | ❌ Pendiente (después de 2 y 3) |
| 5 | Verificar formato Word: Arial 12, interlineado 1.5, márgenes | ⚠️ Verificar |
| 6 | Numeración de páginas en ángulo superior derecho | ⚠️ Verificar |
| 7 | Sangría 5 espacios en primer renglón de cada párrafo | ⚠️ Verificar |
| 8 | Carátula completa | ⚠️ Verificar |
| 9 | Introducción presente | ⚠️ No se encuentra en el DOCX — verificar |

**Nota sobre la Introducción:** El índice del documento no muestra una sección "Introducción" explícita. El lineamiento la requiere como elemento documental. Confirmar si existe antes del desarrollo o si debe agregarse.
