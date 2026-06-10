export const KILL_CHAIN = [
  {time:"2026-06-15 08:14", type:"PHISHING", color:"t-amber", logc:"lt-amber", tech:"T1566.001", host:"endpoint-soporte-07", desc:"Apertura de adjunto malicioso factura_Q28000.docx.exe — usuario a.garcia@finred.gt"},
  {time:"2026-06-15 08:15", type:"EXECUTION", color:"t-red", logc:"lt-red", tech:"T1059.001", host:"endpoint-soporte-07", desc:"Ejecución PowerShell — descarga de loader desde 185.44.21.10"},
  {time:"2026-06-15 09:44", type:"C2 COMMS", color:"t-red", logc:"lt-red", tech:"T1071.001", host:"endpoint-soporte-07", desc:"Beacon HTTPS/443 hacia infraestructura C2, intervalo 60s"},
  {time:"2026-06-15 11:14", type:"RECON", color:"t-amber", logc:"lt-amber", tech:"T1046", host:"endpoint-soporte-07", desc:"Escaneo de red 172.16.10.0/24, puertos 22/3389/445"},
  {time:"2026-06-15 12:01", type:"DETECCIÓN ZT", color:"t-cyan", logc:"lt-cyan", tech:"EDR-BEH-C2-BLOCK", host:"endpoint-soporte-07", desc:"EDR behavioral bloquea IP en feed OTX LockBit 3.0 — cuarentena automática (T0+3h47m)", detect:true},
  {time:"2026-06-16 11:00", type:"CRED ACCESS", color:"t-red", logc:"lt-red", tech:"T1003", host:"endpoint-soporte-07", desc:"Volcado de LSASS mediante reflective DLL"},
  {time:"2026-06-16 12:14", type:"PERSISTENCE", color:"t-red", logc:"lt-red", tech:"T1053.005", host:"endpoint-soporte-07", desc:"Tarea programada disfrazada de WindowsDefenderUpdate"},
  {time:"2026-06-16 14:36", type:"LATERAL", color:"t-purple", logc:"lt-purple", tech:"T1570", host:"portal-soporte-01", desc:"SMB exec hacia prod-app-srv-01 con herramienta tipo psexec"},
  {time:"2026-06-16 15:19", type:"LATERAL", color:"t-purple", logc:"lt-purple", tech:"T1021.001", host:"prod-app-srv-01", desc:"Login RDP exitoso vía NTLM, origen portal-soporte-01"},
  {time:"2026-06-18 02:15", type:"EXFILTRATION", color:"t-red", logc:"lt-red", tech:"T1048", host:"db-transac-01", desc:"Volcado de BD transaccional — 62 tablas, 847,320 registros"},
  {time:"2026-06-18 02:59", type:"EXFILTRATION", color:"t-red", logc:"lt-red", tech:"T1048", host:"db-transac-01", desc:"Carga de 3.4 GB hacia 91.220.163.47 vía HTTPS/443"},
  {time:"2026-06-19 03:54", type:"DEF EVASION", color:"t-red", logc:"lt-red", tech:"T1562.001", host:"prod-app-srv-01", desc:"Terminación forzada de agente EDR 4.2.1"},
  {time:"2026-06-19 03:55", type:"DEF EVASION", color:"t-red", logc:"lt-red", tech:"T1562.001", host:"prod-srv-03", desc:"Terminación forzada de agente EDR 4.2.1"},
  {time:"2026-06-19 04:01", type:"IMPACT", color:"t-impact", logc:"lt-red lt-impact", tech:"T1486", host:"db-transac-01", desc:"Inicio de cifrado AES-256 sobre /data/transac/*.db — proceso lockbit3.exe", impact:true},
  {time:"2026-06-19 04:02", type:"IMPACT", color:"t-impact", logc:"lt-red lt-impact", tech:"T1486", host:"auth-srv-01", desc:"Cifrado de configuraciones /etc/app/*.conf y /var/lib/auth/", impact:true},
  {time:"2026-06-19 04:03:30", type:"IMPACT BLOQUEADO", color:"t-cyan", logc:"lt-cyan", tech:"T1486", host:"backup-vault", desc:"WORM lock activo — ENCRYPT_BLOCKED, acceso denegado", detect:true},
  {time:"2026-06-19 04:03:45", type:"KRI ALERT", color:"t-amber", logc:"lt-amber", tech:"RULE-KRI-01", host:"—", desc:"KRI-07 EDR_DESACTIVADO = 2 (umbral 0) — escalado a CISO"},
  {time:"2026-06-19 04:04:00", type:"KRI ALERT", color:"t-amber", logc:"lt-amber", tech:"RULE-KRI-08", host:"—", desc:"KRI-08 ACCESO_BACKUP_FUERAVENTANA = 1 — escalado a Jefe de Infraestructura"},
  {time:"2026-06-19 04:04:15", type:"KILL CHAIN", color:"t-cyan", logc:"lt-cyan", tech:"GRC-FinRed-0601", host:"—", desc:"Correlación T1566+T1003+T1570+T1562+T1486 — Aislamiento + revocación de sesiones", detect:true},
];

export const TOP_RISKS = [
  {id:"RIE-28", asset:"ACT-10", threat:"Compromiso de endpoint corporativo mediante spearphishing", inherent:25, residual:5.5, eff:78, level:"MUY ALTO", mitre:"T1566.001"},
  {id:"RIE-13", asset:"ACT-05", threat:"Clonación de aplicación móvil en tiendas no oficiales", inherent:20, residual:9.0, eff:55, level:"MUY ALTO", mitre:"T1456"},
  {id:"RIE-21", asset:"ACT-07", threat:"Exfiltración de registros por BOLA/IDOR en API", inherent:20, residual:3.6, eff:82, level:"MUY ALTO", mitre:"T1048"},
  {id:"RIE-30", asset:"ACT-10", threat:"Movimiento lateral por falta de microsegmentación", inherent:20, residual:2.4, eff:88, level:"MUY ALTO", mitre:"T1570"},
  {id:"RIE-16", asset:"ACT-06", threat:"Acceso no autorizado al portal de comercios", inherent:16, residual:3.5, eff:78, level:"ALTO", mitre:"T1566.001"},
  {id:"RIE-01", asset:"ACT-01", threat:"Explotación de vulnerabilidades en servicio de autenticación", inherent:15, residual:3.3, eff:78, level:"ALTO", mitre:"T1190"},
  {id:"RIE-29", asset:"ACT-10", threat:"Ejecución de ransomware sin restricción de intérpretes", inherent:16, residual:3.2, eff:80, level:"ALTO", mitre:"T1059.001"},
  {id:"RIE-19", asset:"ACT-07", threat:"Enumeración masiva por ausencia de rate limiting", inherent:16, residual:3.5, eff:78, level:"ALTO", mitre:"T1190"},
  {id:"RIE-03", asset:"ACT-01", threat:"Sobrescritura de binarios sin runtime inmutable", inherent:15, residual:3.0, eff:80, level:"ALTO", mitre:"T1059.001"},
  {id:"RIE-32", asset:"ACT-10", threat:"Desactivación de EDR por usuario de servicio", inherent:15, residual:3.0, eff:80, level:"ALTO", mitre:"T1562.001"},
];

export const HEATMAP = [
  {p:1,i:1,c:0},{p:1,i:2,c:0},{p:1,i:3,c:0},{p:1,i:4,c:0},{p:1,i:5,c:0},
  {p:2,i:1,c:0},{p:2,i:2,c:0},{p:2,i:3,c:2},{p:2,i:4,c:3},{p:2,i:5,c:5},
  {p:3,i:1,c:0},{p:3,i:2,c:0},{p:3,i:3,c:3},{p:3,i:4,c:8},{p:3,i:5,c:9},
  {p:4,i:1,c:0},{p:4,i:2,c:0},{p:4,i:3,c:1},{p:4,i:4,c:4},{p:4,i:5,c:3},
  {p:5,i:1,c:0},{p:5,i:2,c:0},{p:5,i:3,c:0},{p:5,i:4,c:0},{p:5,i:5,c:1},
];

export const ACTORS = [
  {name:"Operadores RaaS LockBit 3.0", cat:"RaaS", origin:"Internacional", relevance:100, ttps:8, scenarios:6, color:"var(--red)"},
  {name:"APT38 / Lazarus Group", cat:"APT — Estado-Nación", origin:"Corea del Norte", relevance:97, ttps:6, scenarios:5, color:"var(--purple)"},
  {name:"FIN7 / Carbanak", cat:"eCrime", origin:"Europa del Este", relevance:92, ttps:6, scenarios:4, color:"var(--amber)"},
  {name:"Initial Access Brokers", cat:"IAB", origin:"Internacional", relevance:83, ttps:4, scenarios:4, color:"var(--blue)"},
  {name:"Insider Malicioso", cat:"Insider Threat", origin:"Interno", relevance:70, ttps:3, scenarios:3, color:"var(--cyan)"},
];

export const TACTICS = [
  {name:"TA-01 Acceso Inicial", actors:"LockBit RaaS, FIN7, IABs"},
  {name:"TA-02 Ejecución", actors:"LockBit RaaS, FIN7"},
  {name:"TA-03 Persistencia", actors:"LockBit RaaS, APT38"},
  {name:"TA-04 Escalación de Privilegios", actors:"APT38, Insider"},
  {name:"TA-05 Evasión de Defensas", actors:"LockBit RaaS, APT38"},
  {name:"TA-06 Acceso a Credenciales", actors:"LockBit RaaS, FIN7, Insider"},
  {name:"TA-07 Movimiento Lateral", actors:"LockBit RaaS, APT38"},
  {name:"TA-08 Exfiltración / Impacto", actors:"LockBit RaaS, APT38, Insider"},
];

export const ZT_PILLARS = [
  {name:"Identidad", score:0, level:"CRÍTICO", color:"var(--red)"},
  {name:"Dispositivos", score:50, level:"DEFINIDO", color:"var(--amber)"},
  {name:"Redes", score:33, level:"INICIAL", color:"var(--amber)"},
  {name:"Aplicaciones", score:33, level:"INICIAL", color:"var(--amber)"},
  {name:"Datos", score:50, level:"DEFINIDO", color:"var(--amber)"},
];

export const FRAMEWORKS = [
  {name:"ISO/IEC 27001:2022", pct:45, color:"var(--blue)"},
  {name:"COBIT 2019", pct:33, color:"var(--purple)"},
  {name:"NIST CSF 2.0", pct:44, color:"var(--cyan)"},
];

export const KPIS = [
  {id:"KPI-01", name:"Cobertura de MFA", current:87, target:100, unit:"%"},
  {id:"KPI-02", name:"Cobertura de PAM", current:72, target:95, unit:"%"},
  {id:"KPI-03", name:"Accesos Just-in-Time", current:61, target:90, unit:"%"},
  {id:"KPI-04", name:"Revisión de accesos", current:100, target:100, unit:"%"},
  {id:"KPI-05", name:"Cobertura microsegmentación", current:45, target:100, unit:"%"},
  {id:"KPI-06", name:"Cobertura de EDR", current:93, target:98, unit:"%"},
  {id:"KPI-07", name:"Parcheo vulnerabilidades críticas", current:97, target:95, unit:"%"},
  {id:"KPI-08", name:"MTTD (horas)", current:3.78, target:24, unit:"h"},
  {id:"KPI-09", name:"MTTR (horas)", current:4.0, target:8, unit:"h"},
  {id:"KPI-10", name:"Respaldos verificados", current:100, target:100, unit:"%"},
  {id:"KPI-11", name:"Capacitación en seguridad", current:91, target:95, unit:"%"},
  {id:"KPI-12", name:"Resistencia a phishing", current:82, target:90, unit:"%"},
];

export const KRIS = [
  {id:"KRI-01", name:"Intentos de acceso anómalos", current:12, threshold:50},
  {id:"KRI-02", name:"Cuentas privilegiadas sin justificación", current:4, threshold:0},
  {id:"KRI-03", name:"Cambios de privilegios IAM no autorizados", current:0, threshold:0},
  {id:"KRI-04", name:"Apps móviles falsificadas detectadas", current:1, threshold:0},
  {id:"KRI-05", name:"Picos anómalos de consumo de APIs", current:0, threshold:0},
  {id:"KRI-06", name:"Consultas masivas a base de datos", current:0, threshold:0},
  {id:"KRI-07", name:"Desactivaciones de EDR no programadas", current:2, threshold:0},
  {id:"KRI-08", name:"Accesos a respaldos fuera de ventana", current:1, threshold:0},
  {id:"KRI-09", name:"Incidentes de phishing materializados", current:1, threshold:0},
  {id:"KRI-10", name:"Riesgos residuales sobre umbral", current:1, threshold:0},
];

export const TITLES = {
  ejecutivo: ["Resumen Ejecutivo", "Postura de riesgo, retorno de inversión y cumplimiento global"],
  incidente: ["Incidente IR-2026-0601", "Ransomware LockBit 3.0 — Kill chain, MTTD/MTTR y costo-beneficio"],
  riesgos: ["Riesgos & Matriz", "Análisis ISO/IEC 27005:2022 — 39 escenarios, mapa de calor 5×5"],
  amenazas: ["Threat Intelligence", "Actores de amenaza, relevancia y cobertura MITRE ATT&CK"],
  cumplimiento: ["Cumplimiento & Madurez", "KPIs, KRIs, madurez Zero Trust y marcos normativos"],
  forense: ["Evidencia Forense", "Cadena de custodia y consola de eventos SIEM"],
};

export const NAV_ITEMS = [
  {tab:"ejecutivo", icon:"◆", label:"Resumen Ejecutivo"},
  {tab:"incidente", icon:"⚠", label:"Incidente IR-2026-0601"},
  {tab:"riesgos", icon:"▦", label:"Riesgos & Matriz"},
  {tab:"amenazas", icon:"☠", label:"Threat Intelligence"},
  {tab:"cumplimiento", icon:"✓", label:"KPIs / KRIs / ZT"},
  {tab:"forense", icon:"⌂", label:"Evidencia Forense"},
];
