---
name: ai-model-supply-chain
description: Revisa procedencia e integridad de modelos, serialización, dependencias, adaptadores, tokenizadores y datos de entrenamiento.
---

# Cadena de suministro de IA/ML

Activa esta guía cuando el objetivo cargue modelos o artefactos ajenos, instale dependencias o ejecute pipelines de entrenamiento. No atribuyas un resultado extraño al modelo sin localizar la etapa que lo produjo.

1. Enumera la cadena origen → repositorio → descarga → verificación → carga → inferencia o entrenamiento. Registra formato, versión, firma/hash, identidad que publica y permisos de quien carga.
2. Separa dos hipótesis: ejecución al cargar un artefacto o modificación silenciosa del comportamiento del modelo. Revisa formatos de serialización y dependencias en un entorno aislado; no cargues un archivo desconocido en tu Kali de trabajo para inspeccionarlo.
3. Compara artefactos y datos con una versión de control: manifiesto, hash, cambios en adaptadores/tokenizador y conjunto de pruebas de comportamiento. Un hash distinto señala cambio, no demuestra por sí mismo intención maliciosa.
4. Si hay una ruta de publicación controlable, prueba con un artefacto benigno y reversible si la pipeline acepta un origen sin verificar o si cambia la salida. Confirma en registros qué versión se desplegó y qué proceso la cargó.
5. Si no puedes observar la carga o el cambio de salida, conserva la hipótesis como no confirmada. Para un fallo de integridad de paquetes también puede ayudar `signed-artifacts`.

Entrega: etapa vulnerable, identidad y permiso efectivos, comparación con control, evidencia del efecto y condición de parada.

Base temática: material AI-300 aportado por el usuario, cadena de suministro IA/ML (cap. 8). Redacción original.
