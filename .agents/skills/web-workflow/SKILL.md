---
name: web-workflow
description: Analiza aplicaciones con registro, reserva, pago, aprobación, check-in u otros flujos de varios pasos mediante estados y controles reproducibles.
---

# Flujos web y lógica de negocio

Activa esta guía cuando el hallazgo dependa de completar varias acciones HTTP en orden.

1. Dibuja el flujo como estados y transiciones: requisito de cada paso, actor, petición, artefacto emitido y efecto observable. Guarda una ejecución normal completa como control.
2. Para cada hipótesis, cambia una sola dimensión: identidad, orden, parámetro, repetición o tiempo. Mantén iguales cuenta, sesión, objeto y condiciones del control cuando sea posible.
3. Compara el estado final, no solo el código HTTP. Verifica perfil, propiedad del objeto, recibo, token, evento o acceso que la hipótesis predice.
4. Si hay esperas o procesos asíncronos, toma medidas de control y variante con el mismo intervalo. Usa sondeos breves y un límite de tiempo explícito; registra el instante en que cambia el estado.
5. Si una variante falla, determina el primer paso donde diverge del flujo normal. No repitas el ciclo completo cambiando varios campos a la vez.
6. Antes de concluir inyección por un 500 genérico, prueba longitudes crecientes y controles de tiempo: un límite de columna o truncamiento produce el mismo síntoma que un error SQL.
7. Cuando un campo validado acaba en un sink (SQL, comando, plantilla), prueba diferencias de binding —form vs JSON, query vs body, parámetros duplicados o array— y confirma el valor realmente almacenado y el efecto, no solo la respuesta del formulario.

Antes de un nuevo experimento, deja claro: estado inicial, modificación única, resultado esperado, control y condición de parada. Tras ejecutarlo, marca la hipótesis como apoyada, refutada o inconclusa con evidencia.

Referencias: [OWASP WSTG, Business Logic Testing](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/) y [Claude-Red, Business Logic](https://github.com/SnailSploit/Claude-Red/blob/main/Skills/web/offensive-business-logic/SKILL.md).
