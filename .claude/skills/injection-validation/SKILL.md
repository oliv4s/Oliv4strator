---
name: injection-validation
description: Comprueba hipótesis de SQLi, inyección de comandos, SSRF u otras entradas interpretadas mediante controles diferenciales y evidencia de efecto.
---

# Validación de inyecciones

Activa esta guía cuando una entrada del usuario parezca llegar a un intérprete, consulta, URL o proceso externo.

1. Identifica el origen, transformaciones conocidas y punto de consumo. Un campo reflejado o un error genérico no demuestran ejecución.
2. Formula una predicción falsable y elige una sola familia de prueba acorde a la evidencia. Ejecuta un control benigno y una variante que cambie únicamente la propiedad investigada.
3. Para señales de tiempo, alterna control y variante varias veces y compara la distribución con la latencia normal. Para efectos externos, usa un marcador único y comprueba que llegó del servidor objetivo; para efectos internos, consulta el estado por otra vía.
4. Si el flujo tiene varios pasos, confirma que el valor alcanzó el paso que lo consumiría antes de interpretar el resultado. Un rechazo en registro o validación invalida el ensayo posterior.
5. Tras controles negativos repetidos, revisa la suposición sobre codificación, contexto o punto de ejecución. Cierra la hipótesis o cambia de superficie; evita lanzar muchas variantes sin medir.

Entrega una tabla breve con entrada, control, variante, resultado esperado, observado y veredicto. La ausencia de callback o retraso es inconclusa si no se comprobó conectividad o llegada al punto de consumo.

Referencias: [OWASP WSTG, Input Validation](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/) y [Claude-Red, Web Application](https://github.com/SnailSploit/Claude-Red).
