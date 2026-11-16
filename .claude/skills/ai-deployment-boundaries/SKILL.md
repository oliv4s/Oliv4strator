---
name: ai-deployment-boundaries
description: Analiza permisos y secretos de servicios cloud, contenedores y Kubernetes que alojan modelos o pipelines de IA.
---

# Infraestructura de despliegue de IA

Activa esta guía cuando haya evidencia de servicio de inferencia, MLOps, registro de modelos, cloud ML o Kubernetes. Aplica el mismo rigor que a cualquier infraestructura: la etiqueta «IA» no implica una vulnerabilidad.

1. Mapea entrada pública, servicio de inferencia, almacenamiento de datos/modelos, registro, pipeline y cuentas de servicio. Anota qué identidad usa cada componente y qué recurso puede leer o modificar.
2. Comienza por comprobaciones de lectura: endpoints expuestos, metadatos, roles, políticas, secretos visibles, montajes y permisos RBAC observados. Relaciona cada permiso con una acción concreta que permitiría, sin confundir visibilidad de un nombre con acceso efectivo.
3. Si existe una ruta entre identidades, valida cada salto por separado con una operación mínima dentro del alcance. Un token encontrado, una política amplia o un pod privilegiado no prueban que el salto funcione.
4. En contenedores y orquestación, distingue cuenta de pod, namespace, permisos de API, volúmenes y acceso al host. Para ML, revisa además artefactos compartidos y componentes de inicialización que escriben modelos o configuración.
5. Anota el impacto sobre confidencialidad, integridad del modelo y ejecución. Detén la prueba si el siguiente recurso cloud, clúster o host no está incluido en el alcance aprobado.

Entrega: tabla identidad → permiso → recurso → prueba → resultado, con la ruta de escalada confirmada y sus saltos pendientes.

Base temática: material AI-300 aportado por el usuario, infraestructura y despliegue (cap. 9). Redacción original.
