# Arquitectura de Oliv4strator

## Componentes

```text
Codex CLI / Claude Code CLI
    | instrucciones AGENTS.md + CLAUDE.md
    v
MCP (codex_lab_mcp.py) / CLI adapters
    +-- alcance y politica: scope_target.py, program_policy.py
    +-- estado por caso: casebook.py, lab_bridge.py
    +-- contexto compacto: oliva_context.py
    +-- checkpoint y telemetria: harness/efficiency/
    +-- ciclo de vida local: oliva_artifact, workspace.py, artifacts.py
    v
cases/<case_id>/         - expediente, eventos, pruebas retenidas
memory/                  - lecciones generales (locales)
programs/<program_id>/   - politicas reales, locales e ignoradas
work/temp/               - scratch por caso y sesion
work/quarantine/         - scratch recuperable tras finalizar
```

## Principios

1. **Modelo independiente:** Codex y Claude aportan el modelo y las herramientas propias; el MCP comparte registros y controles.
2. **Perfiles bajo demanda:** LAB, BB-Web y BB-Code cargan solo instrucciones relevantes. Los nombres heredados `lab_*` se conservan por compatibilidad.
3. **Datos del caso separados:** evidencias y secretos nunca entran en skills ni memoria metodologica global. Los expedientes no se versionan.
4. **Politica fuera del prompt:** el alcance efectivo y las aprobaciones del cliente no se sustituyen con texto de instrucciones.
5. **Resultados verificables:** checkpoint compacto e informacion detallada recuperable por referencia; no se descartan evidencias para ahorrar tokens.
6. **Sin limpieza remota automatica:** el gestor solo toca workspaces locales identificados como propios.

## Ciclo de vida de archivos

```text
Inicio: scripts/oliva_run.py -> work/temp/<case>/<session>
Durante: registrar (retain con evidence_id / discard explicito / unknown)
Finalizacion controlada: oliva_artifact(finalize)
    retain  -> cases/<case>/evidence/retained-artifacts/ + SHA-256
    discard -> eliminar solo si coincide el hash y no es una evidencia
    unknown -> work/quarantine/<case>/<session>/
Interrupcion -> work/temp sin borrar ni declarar tarea completada; el lanzador informa del estado
Mantenimiento -> previsualizacion; purga de cuarentenas >= 7 dias
```

`TMPDIR` solo afecta a programas que respetan esa variable. No captura rutas `/tmp/...` escritas directamente.

## Limites de la automatizacion

- `oliva_artifact(finalize)` debe invocarse tras verificar que no quedan procesos relevantes; no se ejecuta automaticamente si el cliente finaliza sin la llamada.
- Los datos retenidos requieren IDs de evidencia existentes. Los archivos no clasificados se conservan hasta la cuarentena.
- El hook puede observar comandos, pero no actua como sandbox universal para las herramientas nativas de los clientes.
- La gestion de alcance y de permisos permanece independiente de los scripts de mantenimiento.

Ver [Mantenimiento](MAINTENANCE.md) para operaciones de recuperacion y limpieza.
