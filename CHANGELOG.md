# Historial de Oliv4strator

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
