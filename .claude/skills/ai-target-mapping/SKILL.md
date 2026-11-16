---
name: ai-target-mapping
description: Reconoce componentes de IA y modela flujos de datos, identidades y límites de confianza antes de probar agentes, RAG o modelos.
---

# Mapa de un objetivo con IA

Activa esta guía solo cuando una aplicación, API, repositorio o configuración muestre una función de IA. Un puerto HTTP por sí solo no basta. Combina reconocimiento y modelado de amenazas; usa `service-triage` para el inventario de red ordinario.

1. Registra la señal concreta: interfaz de chat, API de inferencia, modelo servido, retriever, base vectorial, agente, MCP, A2A, pipeline de entrenamiento o artefacto de modelo. Separa los componentes confirmados de los supuestos.
2. Dibuja el recorrido de una solicitud: usuario → aplicación → orquestador/modelo → herramienta o recuperación → dato/acción → respuesta. Para cada salto apunta quién controla la entrada, identidad efectiva, autenticación y salida observable.
3. Empieza por configuración y tráfico ya observados; después elige una consulta inocua que distinga dos arquitecturas posibles. Compara respuestas y metadatos con un control. No deduzcas un proveedor o un modelo solo por el estilo de texto.
4. Prioriza límites donde datos de menor confianza pueden convertirse en instrucciones, donde el agente ejecuta acciones con privilegios mayores o donde la recuperación omite permisos del usuario.
5. Mantén un registro de supuestos con evidencia, confianza, prueba discriminante y estado. Descarta rutas que requieran IP, cuenta o servicio fuera del alcance aprobado; solicita ampliación de alcance antes de tocar otro destino.

Entrega: mapa breve de componentes y límites de confianza, dos hipótesis verificables y la siguiente prueba de menor coste. Revisa el mapa tras cada hallazgo que cambie el flujo real.

Base temática: material AI-300 aportado por el usuario, reconocimiento (cap. 2), modelado de amenazas (cap. 10), introducción (cap. 1) y capstone (cap. 11). Redacción original; no contiene instrucciones de los laboratorios.
