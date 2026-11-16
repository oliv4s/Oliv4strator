---
name: ai-embeddings
description: Evalúa exposición de bases vectoriales y viabilidad de inferencia o reconstrucción a partir de embeddings.
---

# Vectores y reconstrucción

Activa esta guía solo si hay acceso observado a vectores, a una API de similitud o a metadatos de una base vectorial. Una aplicación RAG sin ese acceso se investiga con `ai-rag-pipelines`.

1. Determina colección, volumen, dimensión, normalización, metadatos disponibles y modelo de embedding probable. Verifica el modelo mediante una muestra de control cuando sea posible; la dimensión por sí sola no lo identifica.
2. Define qué pregunta responden los vectores: pertenencia de un candidato, atributo aproximado o reconstrucción de texto. Prioriza los fragmentos relevantes y calcula el coste antes de procesar toda la colección.
3. Compara candidatos o reconstrucciones con controles negativos y una muestra de validación. Una similitud alta sugiere proximidad semántica, no identidad textual ni recuperación exacta de un secreto.
4. Si usas reconstrucción, registra modelo, parámetros, umbral, incertidumbre y coste. Los tokens de alta entropía y el texto largo suelen ser poco recuperables; verifica cualquier hallazgo contra una fuente independiente autorizada.
5. Detén la vía cuando no puedas identificar el modelo, la ventaja frente al control sea débil o el coste de cómputo supere el valor de la hipótesis. No conviertas un resultado de laboratorio en una afirmación universal.

Entrega: hipótesis, acceso real a vectores, controles, medida de calidad y conclusión con incertidumbre.

Base temática: material AI-300 aportado por el usuario, embeddings (cap. 6). Redacción original; no incluye scripts del curso.
