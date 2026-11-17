# CyberGhost: revisión del perfil

Fuente: [programa público de YesWeHack](https://yeswehack.com/programs/cyberghost-bug-bounty-program). Consultado el 16 de noviembre de 2026; la página indica actualización el 5 de noviembre de 2026. La política local es un borrador y se activa únicamente con `lab_program_activate` y aprobación humana.

## Alcance automatizado

`lab_program_check`, `lab_program_http`, `lab_program_discover` y `lab_program_paths` pueden trabajar con HTTPS en `cyberghost.com`, `cyberghost.app`, sus subdominios indicados por el programa y `api.cyberghostvpn.com`. El perfil distingue `*.cyberghostvpn.com` de `cyberghostvpn.com`: el dominio raíz no queda autorizado. Solo se usa el puerto 443; redirecciones a otros orígenes no se siguen. El sufijo exigido se añade al User-Agent.

El perfil no fija una cifra oficial de peticiones por hora: el programa no publica una. Al activar, Oliva debe omitir `hourly_limit` y `min_interval_seconds` si el operador no ha pedido valores concretos. La herramienta detiene lotes ante 429/503 y el agente debe usar rutas observadas y lotes pequeños, evitando escáneres de mucho tráfico.

## Alcance que requiere flujo aparte

La tabla también menciona servidores VPN, aplicaciones de escritorio y móviles y extensiones oficiales. Están registrados como `manual_assets` para que Oliva los reconozca, pero las herramientas HTTP no autorizan análisis de binarios, escaneo de IPs VPN ni tráfico a tiendas de aplicaciones. Para un servidor VPN se necesita el endpoint obtenido de una app oficial y una captura de la IP y ubicación asignadas. Cualquier ampliación del flujo debe modelar esa procedencia antes de operar.

## Informe

Al verificar una candidata con una o dos comprobaciones de bajo impacto, registrar la evidencia con `lab_program_finding`, detener esa vía y revisar manualmente el borrador. El reporte necesita impacto, remedio, prueba y pasos reproducibles. Redactar cualquier dato personal y no publicar la vulnerabilidad.

Antes de iniciar una sesión, consultar de nuevo la página oficial. Si cambian reglas o activos, actualizar `source.txt` y `policy.draft.json`; el hash obliga a reactivar el programa tras cualquier cambio.
