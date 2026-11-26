# Oliv4strator

Orquestador modular para evaluaciones de seguridad **autorizadas**. Compatible con **Codex CLI** y **Claude Code CLI**; organiza alcance, herramientas, evidencias, memoria y sesiones locales.

## Inicio rápido (Kali Linux)

```bash
git clone https://github.com/oliv4s/Oliv4strator.git
cd Oliv4strator
python3 scripts/bootstrap.py
```

Necesitas Python 3, un cliente Codex o Claude configurado y sus dependencias. `bootstrap.py` prepara la configuración local del MCP. Comprueba las herramientas con `/mcp` dentro del cliente.

**Iniciar una sesión con temporales propios:**

```bash
python3 scripts/oliva_run.py --case CASE_ID --client codex --profile deepseek
```

Sustituye `CASE_ID` por el identificador local del expediente autorizado. Para Claude usa `--client claude` sin `--profile`. Al salir, el lanzador muestra si el workspace quedó activo o finalizado, sin borrar nada por su cuenta. Conserva los permisos normales del cliente; **no desactiva sus aprobaciones**.

## Perfiles

| Perfil | Uso |
|---|---|
| LAB | Laboratorios y ejercicios autorizados. |
| BB-Web | Programas web con política y activos declarados. |
| BB-Code | Revisión de código y repositorios autorizados. |

Los ejemplos `programs/demo-program/` y `programs/demo-code/` son ficticios. Los perfiles de programas reales y sus reglas se guardan **solo localmente**, fuera de Git. No utilices un ejemplo como autorización real.

## Consulta de CVEs y resultados compactos

`oliva_research` consulta automaticamente metadatos publicos de **NVD**, **GitHub Advisories** y repositorios publicos GitHub (sin modificar el alcance de la evaluacion). Las respuestas son cortas, citan la fuente y se guardan temporalmente en cache. No descarga ni ejecuta herramientas; el codigo externo requiere revision y aprobacion independientes.

`oliva_output` permite leer fragmentos de archivos de salida largos guardados en el workspace del caso, sin enviar todo el log al modelo. No intercepta las herramientas nativas de Codex. `oliva_diagnostics` informa de bloqueos del hook sin revelar comandos o secretos; las aprobaciones nativas de Codex siguen siendo independientes.

## Sesiones, evidencias y limpieza

- Cada sesión usa `work/temp/<case>/<session>/`.
- El agente puede registrar evidencias verificadas para conservarlas en `cases/<case>/evidence/retained-artifacts/`.
- Tras finalizar de forma controlada, `oliva_artifact(finalize)` genera un resumen en `cases/<case>/session-reports/`, elimina los temporales explícitamente descartables que no hayan cambiado y mueve los desconocidos a `work/quarantine/`.
- **Si Codex/Claude se interrumpe, no se borra nada automáticamente.** La cuarentena se mantiene al menos siete días y puede restaurarse.

```bash
# Ver sesiones sin leer su contenido
python3 scripts/oliva_sessions.py list

# Comprobar una sesión concreta
python3 scripts/oliva_workspace.py status --case CASE_ID --session SESSION_ID

# Vista previa de cuarentenas caducadas (no borra nada)
python3 scripts/oliva_sessions.py prune

# Borrar solo cuarentenas elegibles, después de revisar
python3 scripts/oliva_sessions.py prune --apply
```

Para restaurar una sesión, gestionar un cierre interrumpido y conocer las limitaciones de `/tmp`: [Mantenimiento](docs/MAINTENANCE.md).

## Arquitectura y verificación

```text
Codex / Claude
  -> AGENTS.md + skills bajo demanda
  -> MCP local (codex_lab_mcp.py)
  -> expedientes, memoria, alcance y herramientas
  -> work/temp (trabajo) / cases (evidencia) / work/quarantine (recuperación)
```

El núcleo es compartido y las skills son específicas por perfil. La memoria no reentrena los modelos: guarda conocimientos locales para consulta selectiva. El consumo de tokens se compara con pruebas reproducibles, no a partir de una sola máquina.

- [Arquitectura](docs/ARCHITECTURE.md) · [Mantenimiento](docs/MAINTENANCE.md) · [Cambios](CHANGELOG.md)
- [Diseño del harness](harness/README.md) · [Ejemplos de programa](programs/demo-program/)

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -q
python3 scripts/validate_skills.py
git status --short
```

**Privacidad y seguridad:** `cases/`, `memory/`, `work/`, credenciales y programas reales no deben publicarse. El alcance debe validarse antes de cualquier operación externa. El cierre local nunca borra artefactos de sistemas remotos ni el `/tmp` global.
