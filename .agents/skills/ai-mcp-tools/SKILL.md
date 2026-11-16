---
name: ai-mcp-tools
description: Examina esquemas, descripciones, salidas y permisos efectivos de herramientas MCP conectadas a agentes.
---

# Herramientas MCP

Activa esta guía cuando se observe configuración MCP, transporte o llamadas de herramientas de un servidor MCP. Un servicio JSON-RPC cualquiera no demuestra MCP.

1. Inventaría servidor, transporte, herramientas, esquemas, descripciones, recursos accesibles y credenciales efectivas. Distingue lo que promete la descripción de los permisos del proceso que ejecuta la herramienta.
2. Traza la entrada de usuario → selección de herramienta → argumentos → operación → resultado → siguiente decisión del agente. Señala texto controlable en descripciones y respuestas que podría confundirse con instrucciones.
3. Con un recurso de prueba dentro del alcance, compara comportamiento previsto y real para permisos, rutas y parámetros. Comprueba autorización en el servidor, normalización de rutas y resolución de enlaces antes de afirmar un escape.
4. Si una herramienta devuelve contenido no fiable, verifica si cambia la decisión posterior del agente mediante una prueba controlada. La mera presencia de una instrucción en la salida no es explotación.
5. Para cadenas entre herramientas, anota identidad y permiso en cada salto; no supongas que una restricción declarada por el agente se aplica en el servidor. Detén la cadena en cuanto el siguiente destino quede fuera de la IP o servicios autorizados.

Entrega: matriz herramienta → entrada → privilegio real → control probado → efecto. Diferencia fallo del modelo, fallo de autorización y fallo del servidor.

Base temática: material AI-300 aportado por el usuario, MCP y superficies de herramientas (cap. 7), con cruces al capítulo 8. Redacción original.
