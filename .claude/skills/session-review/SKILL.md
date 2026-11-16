---
name: session-review
description: Revisa una sesión HTB concluida o atascada, mide fallos y mejora una skill o método generalizable con evidencia y contrapruebas.
---

# Revisión y mejora de metodología

Activa esta guía al alcanzar el objetivo, al detener una sesión o tras una secuencia larga sin evidencia nueva. No realices nuevas acciones de red durante la revisión.

1. Llama `lab_review`, `lab_case` y `lab_focus(action=status)`. Resume objetivo, tiempo, llamadas, líneas agotadas, hipótesis abiertas, pruebas negativas y avance verificado. Distingue «herramienta completada» de «efecto confirmado».
2. Identifica hasta dos fallos transferibles. Para cada uno, cita eventos o intentos concretos, la decisión que tomó el agente, la observación que la contradice y una alternativa de menor coste. Examina si el problema era de herramienta, razonamiento o conocimiento.
3. Revisa las skills y `lab_memory` antes de añadir algo. Si la pauta ya existe, refuérzala con `lab_method`; evita una skill duplicada o una regla basada en el nombre de una máquina.
4. Para una mejora nueva, escribe precondición observable, prueba mínima, criterio positivo, criterio negativo y límite de parada. Construye un contraejemplo donde la regla sería incorrecta. Si la evidencia no permite distinguir ambos casos, déjala como hipótesis del caso, no como metodología global.
5. Edita una skill solo cuando el cambio sea general y la prueba de este caso revele una omisión real. La fuente canónica es `.agents/skills/<nombre>/SKILL.md`. Mantén el cambio corto y conserva la atribución de fuentes. Desde la raíz del proyecto ejecuta `python3 scripts/sync_skills.py` y `python3 scripts/validate_skills.py` para actualizar Claude Code.
6. Guarda en la carpeta `cases/<destino>/review-YYYYMMDD.md` las métricas, IDs de evidencia, cambios hechos, contraprueba y qué medir en la siguiente ejecución. En el chat informa de una mejora concreta y una limitación pendiente.

Los laboratorios de [PortSwigger Web LLM attacks](https://portswigger.net/web-security/llm-attacks) y [Lakera Agent Breaker](https://play.lakera.ai/agent-breaker) sirven para probar resistencia a instrucciones maliciosas en contenido externo y uso indebido de herramientas. Evalúan esa robustez por separado de la tasa de resolución de HTB.
