---
name: service-triage
description: Prioriza la enumeración de puertos, banners, vhosts y aplicaciones de una IP autorizada antes de elegir una vía de acceso.
---

# Triaje de superficie

Activa esta guía cuando aparezca un objetivo nuevo o cambie el inventario de servicios.

1. Separa lo observado de lo inferido: puerto y estado, protocolo, banner, redirecciones, nombres de host y contenido. Conserva el inventario al ampliar el escaneo.
2. Para cada servicio abierto, pregunta qué interacción es posible sin credenciales y qué dato faltante distinguiría las rutas plausibles. Prefiere una sonda corta que descarte varias hipótesis antes que un barrido amplio.
3. En HTTP, compara la IP con los nombres revelados por redirecciones, certificados o la propia aplicación. Una respuesta diferente con otro `Host` indica una superficie distinta; registra ambos contextos.
4. Construye un mapa de rutas, parámetros, acciones y roles a partir de páginas y JavaScript observados. Prioriza funcionalidades que aceptan entrada, cambian estado o emiten artefactos.
5. Si una sonda no aporta señal, anota qué descartó y cambia de pregunta. No aumentes el volumen de peticiones solo porque el primer resultado fue negativo.

Entrega al agente principal: hechos con sus IDs de evidencia, las dos vías mejor sustentadas, la prueba discriminante más barata para cada una y el motivo para aplazar el resto.

Referencias: [OWASP WSTG, Information Gathering](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/01-Information_Gathering/) y [Claude-Red, Reconnaissance](https://github.com/SnailSploit/Claude-Red).
