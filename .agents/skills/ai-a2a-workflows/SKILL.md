---
name: ai-a2a-workflows
description: Analiza descubrimiento, identidad, enrutamiento y confianza entre agentes A2A y orquestadores multiagente.
---

# Flujos entre agentes

Activa esta guía si hay tarjetas de agente, registro de capacidades, delegación entre agentes o un orquestador multiagente. No asumas A2A por ver varios endpoints con nombres de agentes.

1. Enumera tarjetas y capacidades observadas, endpoints, autenticación de registro, identidad anunciada y servicio que resuelve cada destino. Traza qué agente recibe qué datos y quién valida sus respuestas.
2. Ejecuta una tarea inocua y registra la secuencia esperada: selección, procesamiento, revisión de seguridad y entrega. Una segunda tarea de control permite distinguir cambios de ruta de variación normal del modelo.
3. Si una identidad o una salida puede ser controlada, prueba un cambio mínimo y reversible para saber si el orquestador verifica procedencia, permisos y resultado. Verifica por registros o estado qué agente actuó; una tarjeta publicada no demuestra que haya sido elegida.
4. Para saltos de confianza, compara una entrada de menor privilegio con la misma tarea autenticada y determina dónde se pierde la identidad del solicitante. Revisa si el agente ejecutor aplica sus propias restricciones en vez de confiar en el orquestador.
5. Clasifica el resultado como manipulación de respuesta, omisión de una fase o acción no autorizada solo cuando exista evidencia de ese efecto. Detén la ruta si el siguiente agente o endpoint queda fuera del alcance aprobado.

Entrega: diagrama corto de agentes, identidades y datos; control, prueba discriminante y efecto observado. Si la vía depende de documentos o memoria, carga después `ai-agent-boundaries`.

Base temática: material AI-300 aportado por el usuario, sistemas multiagente y A2A (cap. 4). Redacción original.
