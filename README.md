# 🫒 Oliv4strator

**Oliva** es un agente para laboratorios de seguridad y programas bug bounty autorizados. Corre en **Codex CLI** o **Claude Code CLI** sobre Kali Linux (WSL2 o VM). El modelo razona y elige las pruebas; el proyecto aporta herramientas, alcance, expediente y memoria metodológica.

## Cómo funciona

```text
Codex CLI / Claude Code CLI
       │  AGENTS.md + skills
       ▼
MCP local: codex_lab_mcp.py
       │
       ▼
Núcleo Python: alcance · pruebas · hipótesis · memoria · evidencias
       │
       ├── LAB → HTB, certificaciones y retos; objetivo y flags del prompt
       ├── BB-Web → investigación web con PoC e informe
       └── BB-Code → auditoría estática y dinámica de repositorios con PoC e informe
```

Oliva consulta el estado y los intentos anteriores antes de probar otra vía, verifica listeners antes de conexiones de vuelta y registra evidencias en `cases/`. El prompt del usuario define el destino autorizado y el bridge actualiza el perfil con `lab_scope` o `lab_program_activate`, sin aprobaciones repetidas. `lab_evidence` permite incorporar observaciones hechas con shell o navegador. En BB-Web, el MCP aplica la política a sus solicitudes HTTP; las herramientas nativas quedan disponibles y el agente debe aplicar las reglas del programa al utilizarlas. En BB-Code, las pruebas de código se ejecutan localmente y `lab_code_finding` genera el borrador reproducible.

Las skills enseñan métodos reutilizables, no soluciones por máquina. `memory/` conserva observaciones locales entre sesiones. Las mejoras generales se incorporan a `.agents/skills/` y se copian a Claude con `python3 scripts/sync_skills.py`.

## Arquitectura modular y ciclo de vida (v5)

```text
Codex CLI / Claude Code CLI
    │  AGENTS.md + perfil bajo demanda + skills
    ▼
MCP local: codex_lab_mcp.py
    ├── autorización y herramientas del caso (núcleo existente)
    ├── oliva_context / checkpoint / progress (eficiencia)
    └── oliva_artifact (v5, ciclo de vida LOCAL)
              │
              ├── work/temp/<case_id>/<session_id>/   [activo]
              │        ├── PoC / evidencias verificadas ──► cases/<case_id>/evidence/retained-artifacts/
              │        ├── scratch marcado como discard ──► eliminación tras finalizar
              │        └── archivos no clasificados ──────► work/quarantine/<case_id>/<session_id>/
              │
              └── al finalizar: resumen compacto + cierre idempotente
```

**La autorización, el modelo, la memoria y el almacenamiento tienen responsabilidades separadas.** El gestor de artefactos solo administra archivos **locales** del workspace que creó Oliv4strator. Nunca modifica `/tmp` global, sistemas objetivos ni el alcance de un programa. Los alias `lab_*` siguen disponibles por compatibilidad; el núcleo nuevo utiliza nombres `oliva_*` independientes de LAB, BB-Web y BB-Code.

### Inicio sencillo de una sesión con temporales propios

```bash
cd /home/kali/00_Tools/oliv4strator
python3 scripts/oliva_run.py --case 10.10.10.10 --client codex --profile deepseek
```

El lanzador crea una sesión única y exporta `TMPDIR`, `OLIVA_WORKSPACE`, `OLIVA_CASE_ID` y `OLIVA_SESSION_ID` al cliente. Para Claude sustituye `--client codex --profile deepseek` por `--client claude`. Los programas que usen rutas `/tmp/...` explícitas seguirán fuera del workspace administrado.

### Limpieza al terminar: sin scripts manuales

La instrucción permanente en `AGENTS.md` indica al agente que, **solo tras terminar la tarea y dejar de ejecutar procesos locales**, invoque una vez `oliva_artifact(action="finalize", outcome="completed")`. El gestor entonces:

1. Comprueba el marcador, las rutas y la integridad de las evidencias retenidas.
2. Elimina únicamente temporales registrados expresamente como `discard` cuyo contenido no haya cambiado.
3. Retira el directorio de trabajo activo y lo traslada a una **cuarentena recuperable** con los archivos sin clasificación o de los que existen copias conservadas.
4. Devuelve un resumen pequeño, sin volcar las evidencias al contexto.

La copia útil permanece en `cases/<case_id>/evidence/retained-artifacts/` con SHA-256 y referencias `evidence_id`. La cuarentena se mantiene **al menos siete días**; su eliminación se comprueba automáticamente en cierres posteriores, sin servicio en segundo plano. Si no vuelve a haber actividad, permanecerá hasta una ejecución de mantenimiento. Puede restaurarse con `python3 scripts/oliva_workspace.py restore --case ... --session ...`.

**El cierre depende de una llamada MCP explícita del agente.** Un proceso cancelado o una salida inesperada de Codex *no desencadena limpieza automática*, para no perder trabajo pendiente. El agente debe registrar primero qué PoC, scripts e informes son realmente necesarios; los archivos desconocidos se preservan provisionalmente. Ninguna de estas reglas modifica los permisos de Codex: las aprobaciones reales del cliente siguen vigentes.

Para una máquina más compleja, prioriza conservar progreso y evidencias durante varios checkpoints en lugar de forzar un cierre al primer hito. Consulta [el diseño y limitaciones de v5](harness/efficiency/README.md).

## Cómo aprende Oliva

Cada ejecución deja intentos, controles, hipótesis y PoC en su expediente `cases/`. Al documentar un hallazgo web o de código, el bridge devuelve un `evidence_id`. Oliva revisa los resultados con `lab_review`, que señala `learning_candidates`, y usa `lab_method` para guardar o contrastar una pauta **transferible** en `memory/methods.json`. En BB-Code puede clasificarla como `code_review`. Una pauta nueva empieza como candidata; las observaciones posteriores pueden apoyarla o refutarla.

Este aprendizaje es memoria y revisión de metodología, no entrenamiento de los pesos del modelo. `cases/` y `memory/` son locales e ignorados por Git. Si una mejora debe viajar a otros equipos, Oliva la resume y valida en una skill general de `.agents/skills/` durante la revisión de sesión; no copia una PoC específica como regla universal.

Las instrucciones dadas en otra conversación de Codex no modifican por sí solas este proyecto. Para hacer permanente una regla de trabajo, hay que incorporarla a `AGENTS.md` o a una skill y sincronizar el proyecto al equipo donde se ejecuta Oliva.

## Instalación en Kali

Usa un clon **dentro del sistema de archivos de Kali**, por ejemplo `~/tools/oliv4strator`, para que el agente tenga acceso a tus herramientas y a la VPN. En Windows puedes abrir Kali WSL2; en VMware el procedimiento dentro de Kali es el mismo.

```bash
sudo apt update
sudo apt install -y git python3 nmap sshpass tshark iproute2
git clone <URL-DE-TU-REPOSITORIO> ~/tools/oliv4strator
cd ~/tools/oliv4strator
python3 scripts/bootstrap.py
```

El arranque crea `scope.json` vacío, comprueba el MCP, prepara `.codex/config.toml` con rutas de este equipo y sincroniza las skills de Claude. Repite `python3 scripts/bootstrap.py` después de clonar en otro PC **o actualizar esta versión**: migra las aprobaciones antiguas de `lab_scope` y `lab_program_activate` a automático sin sobrescribir `scope.json` ni `cases/`. Reinicia Codex o Claude para que recarguen el catálogo de herramientas.

### Codex CLI

Instala Codex **en Kali**, inicia sesión y entra al proyecto:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
cd ~/tools/oliv4strator
codex
```

Codex carga la configuración MCP y los hooks de `.codex/` cuando confías en el proyecto. Si avisa que la carpeta no es de confianza, añade a `~/.codex/config.toml` el bloque de ruta absoluta que imprime `python3 scripts/bootstrap.py`. Comprueba `oliva_lab` con `/mcp`. [Instalación oficial de Codex CLI](https://learn.chatgpt.com/docs/codex/cli) · [Configuración de proyecto](https://learn.chatgpt.com/docs/config-file/config-advanced).

### Claude Code CLI

Instala Claude Code **en la misma Kali** y entra al proyecto:

```bash
curl -fsSL https://claude.ai/install.sh | bash
cd ~/tools/oliv4strator
claude
```

En el primer inicio, revisa la confianza del proyecto y acepta el MCP local `oliva_lab`. Comprueba su estado con `/mcp`. `CLAUDE.md` importa las instrucciones compartidas y `.claude/skills/` contiene las mismas skills que Codex. [Instalación oficial de Claude Code](https://code.claude.com/docs/en/setup) · [MCP de proyecto](https://code.claude.com/docs/en/mcp).

## Primera prueba

Conecta primero la VPN del laboratorio en Kali y da al agente una IP o URL **autorizada**. Por ejemplo:

> Oliva, esta IP de HTB está autorizada: `10.10.10.10`. Configura el alcance con `lab_scope`, revisa `lab_status` y `lab_attempts`, y continúa la investigación hasta verificar el objetivo. Registra lo que pruebes y evita repetir intentos sin nueva evidencia.

Para `BB-Web`, pega en el prompt las reglas y activos vigentes del programa. Oliva puede preparar `programs/<id>/source.txt` y `policy.draft.json`, revisarlos y activar el perfil con `lab_program_activate`. `programs/demo-program/` es un ejemplo **ficticio**. Los perfiles reales de `programs/` permanecen locales y fuera de Git; las apps y servidores VPN requieren otro flujo.

Para `BB-Code`, pega las reglas, la URL exacta del repositorio y la ruta de tu checkout local. Oliva puede crear la política con `code_assets`; [demo-code](programs/demo-code/policy.draft.json) muestra la estructura sin autorizar ningún repositorio real. Si el programa solo contiene código, `web_assets` puede ser `[]`. Al activar indicará `profile="BB-Code"` y `checkout_path`; `lab_code_status` comprobará el remoto Git y la revisión local cuando existan. Usará shell para revisar código y ejecutar PoC locales; `lab_code_finding` guardará versión, ubicación, condiciones y pasos reproducibles. Un programa con activos web y código requiere elegir explícitamente `BB-Web` o `BB-Code`.

Al detectar una causa plausible en BB-Code, la skill `prior-art-triage` guía una comparación temprana con avisos y parches públicos. `lab_code_finding` exige registrar qué fuentes se revisaron y la relación con la causa detectada.

El espacio de trabajo de BB-Code sigue esta estructura dentro de la carpeta del programa elegida por el usuario (`-VDP` para un VDP como Ort; usa el tipo real del programa en otros casos). El código original permanece limpio y los archivos de investigación se nombran y redactan en inglés:

```text
<program>-VDP/
├── README.md
├── source/<repository>/
├── pocs/
├── reports/
├── outputs/
└── candidates/
```

Prompts breves para cada perfil:

- **LAB:** «Perfil LAB. Mi objetivo autorizado es `10.10.10.10`; obtén acceso, `user.txt` y `root.txt`. Fija el destino y trabaja de forma autónoma.»
- **BB-Web:** «Perfil BB-Web. Estas son las reglas y activos del programa: [pegar texto]. Investiga el sitio dentro de ese alcance, verifica PoC de bajo impacto y prepara los informes; continúa con otras vías independientes.»
- **BB-Code:** «Perfil BB-Code. El programa incluye `https://github.com/organizacion/repositorio`; el checkout está en `/home/kali/repositorio`. Estas son sus reglas: [pegar texto]. Audita código, confirma candidatos con PoC locales y prepara informes reproducibles.»

## Qué entra en Git

Se versionan el código, las instrucciones, las skills, los ejemplos y los perfiles públicos revisados. `.gitignore` excluye `scope.json`, `cases/`, `runs/`, `artifacts/`, `memory/`, `work/`, `outputs/`, los perfiles privados de `programs/`, credenciales y capturas. Puedes ejecutar Oliva y generar resultados desde el mismo clon sin añadirlos por accidente a un commit. Para mover un expediente o la memoria local a otro equipo, cópialos por un canal privado; las mejoras metodológicas que quieras compartir deben pasar a una skill.

Comprueba el proyecto sin enviar tráfico:

```bash
python3 scripts/validate_skills.py
python3 -m unittest discover -s scripts -p 'test_*.py'
git status --short
```

El historial de cambios del proyecto está en [CHANGELOG.md](CHANGELOG.md).

## Optional context optimizer

This checkout can use the read-only `oliva_context(max_tokens=550)` MCP tool for a bounded session snapshot. In `AGENTS.md`, the always-loaded instructions route the agent to a single on-demand profile: `harness/profiles/lab.md`, `bb-web.md` or `bb-code.md`. Original instructions are archived at `harness/reference/AGENTS.original.md` for review. The snapshot never replaces program-policy checks or explicit approval.

For a smaller MCP *discovery catalog*, launch the CLI with `OLIVA_MCP_PROFILE=LAB`, `BB-Web` or `BB-Code`; leave it unset for full backward compatibility. Restart Codex/Claude and its MCP server when changing the profile. Filtering tools from discovery does **not** enforce scope on shell or browser commands.

Use `python3 oliva_eval.py examples/benchmark-harness.json` for a synthetic, offline baseline-versus-candidate quality and token-cost comparison. Actual token savings on real tasks must be measured using the model provider's token accounting. No lesson or skill is promoted automatically.

## Efficiency instrumentation v2

See [harness/efficiency/README.md](harness/efficiency/README.md). Optional passive MCP monitoring is off unless `OLIVA_WATCH=1`. No native Codex or Claude calls are intercepted.
