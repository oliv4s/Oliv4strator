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
       ├── lab_machine / web_challenge → investigación del laboratorio
       └── bug_bounty → PoC mínima, borrador de hallazgo, revisión humana
```

Oliva consulta el estado y los intentos anteriores antes de probar otra vía, verifica listeners antes de conexiones de vuelta y registra evidencias en `cases/`. Un cambio de destino o la activación de un programa requiere aprobación humana. En bug bounty, las solicitudes HTTP pasan por la política local del programa; tras verificar un hallazgo, Oliva redacta los pasos para reproducirlo y se detiene en esa vía.

Las skills enseñan métodos reutilizables, no soluciones por máquina. `memory/` conserva observaciones locales entre sesiones. Las mejoras generales se incorporan a `.agents/skills/` y se copian a Claude con `python3 scripts/sync_skills.py`.

## Instalación en Kali

Usa un clon **dentro del sistema de archivos de Kali**, por ejemplo `~/tools/oliv4strator`, para que el agente tenga acceso a tus herramientas y a la VPN. En Windows puedes abrir Kali WSL2; en VMware el procedimiento dentro de Kali es el mismo.

```bash
sudo apt update
sudo apt install -y git python3 nmap sshpass tshark iproute2
git clone <URL-DE-TU-REPOSITORIO> ~/tools/oliv4strator
cd ~/tools/oliv4strator
python3 scripts/bootstrap.py
```

El arranque crea `scope.json` vacío, comprueba el MCP, prepara `.codex/config.toml` con rutas de este equipo y sincroniza las skills de Claude. Repite `python3 scripts/bootstrap.py` después de clonar en otro PC. No sobrescribe un `scope.json` existente.

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

Para un programa bug bounty, prepara `programs/<id>/source.txt` y `policy.draft.json` con sus reglas y activos vigentes. Pide a Oliva que los revise y active con `lab_program_activate`. `programs/demo-program/` es un ejemplo **ficticio**. `programs/cyberghost/` es un perfil público revisado para web/API de CyberGhost; sus apps y servidores VPN requieren un flujo distinto y no quedan habilitados por las herramientas HTTP.

## Qué entra en Git

Se versionan el código, las instrucciones, las skills, los ejemplos y los perfiles públicos revisados. `.gitignore` excluye `scope.json`, `cases/`, `runs/`, `artifacts/`, `memory/`, `work/`, `outputs/`, los perfiles privados de `programs/`, credenciales y capturas. Puedes ejecutar Oliva y generar resultados desde el mismo clon sin añadirlos por accidente a un commit. Para mover un expediente o la memoria local a otro equipo, cópialos por un canal privado; las mejoras metodológicas que quieras compartir deben pasar a una skill.

Comprueba el proyecto sin enviar tráfico:

```bash
python3 scripts/validate_skills.py
python3 -m unittest discover -s scripts -p 'test_*.py'
git status --short
```

El historial de cambios del proyecto está en [CHANGELOG.md](CHANGELOG.md).
