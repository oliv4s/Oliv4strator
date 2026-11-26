# Mantenimiento de sesiones y artefactos (solo equipo local)

Este procedimiento no borra archivos del objetivo ni de `/tmp` global. Se limita a las carpetas administradas por Oliv4strator.

## 1. Ver el estado sin borrar nada

```bash
python3 scripts/oliva_sessions.py list
python3 scripts/oliva_sessions.py list --case CASE_ID
python3 scripts/oliva_workspace.py status --case CASE_ID --session SESSION_ID
```

El inventario muestra cantidad de archivos, bytes y estado; no abre ni imprime el contenido de las evidencias. Los workspaces no administrados o con marcadores invalidos se omiten.

## 2. Al terminar normalmente

El cliente llama a `oliva_artifact(action="finalize", outcome="completed")` cuando la tarea esta verificada y han terminado los procesos locales. Los resultados registrados con IDs de evidencia se conservan en `cases/`. Los temporales marcados `discard` se eliminan solo si no han cambiado. Lo restante va a cuarentena recuperable.

**Importante:** el lanzador `oliva_run.py` no asume que una salida con codigo 0 implique que la tarea este terminada. Si se interrumpe la sesion, los archivos se conservan.

## 3. Recuperar una sesion finalizada

```bash
python3 scripts/oliva_workspace.py restore --case CASE_ID --session SESSION_ID
```

Esto restaura el workspace de cuarentena a `work/temp/`, sin reabrir automaticamente la investigacion ni el alcance.

## 4. Quarantine: revisar y purgar

```bash
# Inventario
python3 scripts/oliva_sessions.py list

# Vista previa, sin borrado
python3 scripts/oliva_sessions.py prune

# Elimina solo cuarentenas finalizadas y elegibles tras 7 dias
python3 scripts/oliva_sessions.py prune --apply
```

La purga comprueba marcador de propiedad, antiguedad, actividad reciente, directorios y enlaces; en caso de duda omite el elemento. Una finalizacion MCP tambien puede purgar cuarentenas antiguas como mantenimiento ocasional. **No existe un daemon en segundo plano ni limpieza automatica basada en la hora.**

## 5. Sesion activa abandonada

```bash
# Inspecciona primero
python3 scripts/oliva_workspace.py inspect --case CASE_ID --session SESSION_ID

# Vista previa de borrado manual de un workspace activo (>24h por defecto)
python3 scripts/oliva_workspace.py clean --case CASE_ID --session SESSION_ID
```

`clean --apply` existe para casos excepcionales; no lo ejecutes mientras haya procesos en curso ni si faltan evidencias por conservar. Es irreversible para ese workspace. Prioriza reanudar la sesion, clasificar archivos y finalizar de forma controlada. La opcion `--min-age-hours` reduce el umbral de antiguedad y debe manejarse con cuidado.

## 6. Datos publicados accidentalmente

Los perfiles reales bajo `programs/` estan ignorados, pero Git puede seguir archivos agregados antes de configurar `.gitignore`. Revisa `git ls-files programs/`, y retira los perfiles particulares del indice sin incluirlos en futuros commits. Esto **no reescribe** el historial ya publicado; si hubo secretos, revocalos y planifica una limpieza del historial por separado.

## Informe de cierre v5.2

Cuando `oliva_artifact(action="finalize")` termina, se guarda un resumen de recuentos en
`cases/<case_id>/session-reports/<session_id>.json` (carpeta ignorada por Git).
Incluye `retained`, `discarded`, `quarantined`, resultado y fecha. No guarda
argumentos de comandos ni salidas completas. Si una interrupcion ocurre antes
del cierre, el workspace permanece activo.

`oliva_diagnostics` resume los bloqueos causados por el hook local. **No**
registra ni evita los permisos obligatorios del cliente Codex o Claude.

## Consulta documental y salidas largas

- `oliva_research`: NVD y advisories oficiales con cache local de 6 h y limites de peticiones.
- `oliva_output`: lectura por fragmentos de logs de texto bajo el workspace de la sesion.
- No usar `lab_scope` para incorporar fuentes publicas; el alcance se reserva para el objetivo.
- Descargar o ejecutar herramientas de terceros continua separado y requiere revision.
