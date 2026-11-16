---
name: signed-artifacts
description: Razona sobre QR, JWT, enlaces firmados, tickets y HMAC sin confundir decodificación, modificación y aceptación del servidor.
---

# Artefactos firmados

Activa esta guía si la aplicación emite un artefacto que contiene datos y una firma o MAC.

1. Separa formato, contenido y mecanismo de integridad. Obtén al menos dos artefactos legítimos cambiando un único campo conocido; compara qué bytes cambian y cuáles permanecen estables.
2. Comprueba primero el comportamiento normal: qué componente emite el artefacto, qué componente lo verifica y qué efecto produce usarlo una vez.
3. Modifica un campo inocuo sin recalcular la firma. Si el servidor lo acepta, determina si realmente verificó la integridad o si leyó datos de otra fuente.
4. Si el artefacto se rechaza, no concluyas que una clave deriva de un campo visible por parecido de longitud o codificación. Contrasta cualquier hipótesis de derivación con varios artefactos y verifica bytes exactos fuera de línea antes de enviar un candidato.
5. Distingue un token reutilizable de uno ligado a usuario, objeto, tiempo o estado. Una firma válida en un contexto no implica aceptación en otro.

Registra estructura observada, campos controlables, prueba de alteración, respuesta del verificador y qué hipótesis quedó descartada. Limita las conjeturas de clave sin evidencia nueva.

Referencias: [OWASP WSTG, JWT](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens/) y [ctf-skills, web/crypto](https://github.com/ljagiello/ctf-skills).
