---
name: linux-post-access
description: Tras confirmar una sesión Linux en el laboratorio, enumera permisos y vías de escalada con pruebas basadas en hechos.
---

# Acceso inicial y escalada Linux

Activa esta guía solo después de confirmar ejecución como un usuario del objetivo.

1. Confirma identidad y contexto (`id`, grupos, directorio, sistema) y conserva la evidencia. Un proceso SSH con código de salida cero no sustituye la comprobación de identidad.
2. Comprueba primero permisos explícitos y superficies alcanzables: `sudo -l`, grupos, capacidades, binarios SUID, servicios locales, tareas programadas y archivos de configuración que el usuario puede leer o modificar.
3. Para cada candidato, escribe la relación concreta entre permiso observado y efecto privilegiado esperado. Prueba la precondición de forma acotada antes de usar una cadena completa.
4. Si un permiso depende de comodines o rutas, compara la regla exacta con el comportamiento real del programa. Evita asumir que el nombre de una herramienta implica privilegio efectivo.
5. Verifica la identidad tras el cambio (`uid=0` para root) y solo entonces consulta los objetivos de laboratorio. Si falla, registra el punto exacto de ruptura y el siguiente permiso a investigar.

Entrega un mapa de permisos observados, candidatos ordenados por evidencia y coste, y la prueba mínima que confirma o descarta cada vía.

Referencias: [Claude-Red, Privilege Escalation](https://github.com/SnailSploit/Claude-Red) y [red-run, fases de assessment](https://github.com/blacklanternsecurity/red-run).
