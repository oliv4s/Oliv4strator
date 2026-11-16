---
name: auth-boundaries
description: Examina autenticación, sesiones, cambios de contraseña, roles y autorización de objetos con comprobaciones de identidad.
---

# Límites de identidad y autorización

Activa esta guía cuando haya login, registro, recuperación, sesión, JWT, roles o recursos vinculados a usuarios.

1. Establece identidades de control: anónimo y cuenta propia; añade una segunda cuenta de laboratorio si el flujo la requiere. Registra qué acción y recurso corresponde a cada una.
2. Distingue autenticación, autorización y presentación: una interfaz que oculta una función no prueba que el servidor la proteja; un `200` no prueba que el usuario o recurso haya cambiado.
3. Para cada prueba, cambia solo la identidad, el identificador de objeto o un campo de actualización. Comprueba después con una lectura independiente quién quedó autenticado y qué objeto fue modificado.
4. Si hay JWT u otro token, decodificarlo solo revela estructura. Una modificación es relevante únicamente si el servidor acepta el token y cambia efectivamente los permisos o datos accesibles.
5. En cambios de contraseña, verifica por separado qué identidad valida la contraseña actual y qué identidad recibe la actualización. Mantén una cuenta de control para evitar confundir pérdida de sesión con éxito.

Registra la matriz actor × acción × recurso, el control positivo, el control negativo y el efecto observable. Si una credencial falla por SSH, clasifícala como autenticación fallida aunque el proceso haya terminado correctamente.

Referencias: [OWASP WSTG, Authentication and Authorization](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/) y [OWASP WSTG, JWT](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/10-JSON_Web_Tokens/).
