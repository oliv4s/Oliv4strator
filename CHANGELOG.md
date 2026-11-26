## 2026-11-26 — v5: ciclo de vida automático de artefactos locales

- Nueva herramienta MCP `oliva_artifact`: conserva evidencias referenciadas y finaliza sesiones locales.
- Al cerrar, elimina temporales explícitos no modificados y mueve los desconocidos a una cuarentena recuperable.
- Cuarentena mínima de siete días, expirada durante finalizaciones posteriores; sin borrar `/tmp` global ni artefactos remotos.
- `scripts/oliva_run.py` proporciona IDs de sesión y `TMPDIR` a Codex/Claude. Las interrupciones no desencadenan limpieza.
- Actualizados README, arquitectura, instrucciones del agente y tests offline.

# Historial de Oliv4strator

## 2026-11-23 — Comprobación temprana de avisos públicos

- La skill `prior-art-triage` compara causa raíz, código y versión con avisos, issues y parches públicos antes de profundizar en una PoC BB-Code.
- `lab_code_finding` exige documentar la comparación; ya no genera borradores con el valor por defecto «No revisados».
- La revisión de sesión trata las candidatas ya públicas como evidencia metodológica, aunque no produzcan un informe.

## 2026-11-17 — Perfiles LAB, BB-Web y BB-Code

- `lab_status.profile` muestra el perfil; los expedientes previos siguen siendo compatibles.
- LAB acepta el destino indicado en el prompt sin notas obligatorias ni aprobaciones repetidas.
- BB-Web conserva la política HTTP, permite herramientas nativas y puede citar su evidencia en las PoC.
- BB-Code acepta repositorios exactos, checkout local, pruebas estáticas y dinámicas, y genera informes con `lab_code_finding`.
- Los informes devuelven un `evidence_id`; `lab_review.learning_candidates` guía la promoción a métodos generales, incluida la fase `code_review`.
- BB-Code adopta una estructura portable con `source`, `pocs`, `reports`, `outputs` y `candidates`, y artefactos en inglés.
- Las aprobaciones de cambio de perfil pasan a automático al ejecutar `scripts/bootstrap.py`; el hook conserva hashes de pruebas nativas sin guardar sus salidas en programas.

## 2026-11-17 — Investigación bug bounty

- El agente recorre hipótesis con controles y variantes observables; la PoC mínima limita la validación final de cada hallazgo, no la exploración completa.
- Perfiles con identidad local pueden aplicar cabeceras obligatorias sin incluir el investigador en Git.
- La extracción de rutas JavaScript y las señales de respuesta HTTP cubren más casos sin aumentar el número de solicitudes.

## 2026-11-16 — Perfil CyberGhost

- Perfil público para los cinco scopes web/API, con subdominios comodín sin incluir implícitamente el dominio raíz.
- Los otros siete scopes de apps, extensiones y servidores VPN quedan documentados para un flujo posterior, sin autorizar escaneos IP con el MCP web.
- El identificador obligatorio se añade al User-Agent; el perfil se activa tras revisar la política vigente.

## 2026-11-16 — Codex CLI y Claude Code CLI

- Un único núcleo Python y MCP local para ambos clientes.
- Instrucciones compartidas en `AGENTS.md`, importadas por `CLAUDE.md`.
- Skills de pentesting y superficies de IA en `.agents/skills/`, sincronizadas con `.claude/skills/`.
- Alcance explícito para laboratorios y programas bug bounty, con activación humana.
- Expediente de intentos, comprobación de listeners, hipótesis y revisión metodológica.
- Perfil bug bounty con PoC mínima y borrador reproducible para revisión manual.
- Datos de pruebas y perfiles reales excluidos de Git mediante `.gitignore`.
