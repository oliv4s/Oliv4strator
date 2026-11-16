---
name: ai-rag-pipelines
description: Evalúa ingestión, recuperación, atribución y permisos de conocimiento en aplicaciones RAG.
---

# Ingestión y recuperación RAG

Activa esta guía cuando haya evidencia de recuperación de documentos o citas vinculadas a una base de conocimiento. Distingue RAG de una respuesta generada sin recuperación.

1. Mapea las dos rutas: quién puede introducir o modificar contenido y cómo una consulta selecciona fragmentos. Identifica colecciones, metadatos, filtros de permisos, caché, citas y el usuario efectivo de la búsqueda.
2. Registra una consulta de control y su fuente. Si puedes introducir un documento de prueba dentro del laboratorio, usa una marca inocua y única; comprueba que se indexa, se recupera y se cita antes de atribuir cualquier cambio al LLM.
3. Para confidencialidad, compara la misma búsqueda entre dos identidades o contextos autorizados. Un fragmento sensible en la respuesta solo es una violación si la identidad de menor privilegio no debía recibirlo y el origen está confirmado.
4. Para integridad, cambia una sola pieza controlada del corpus y repite la consulta. Distingue una cita correcta de obediencia a instrucciones contenidas en el documento; verifica en la secuencia de herramientas o en el estado el efecto alegado.
5. Si una prueba falla, averigua si fue ingestión, recuperación, ranking, filtrado o generación. No optimices el texto de la inyección hasta confirmar que el fragmento llega al modelo. Limita pruebas y revierte documentos de ensayo al cerrar la sesión.

Entrega: ruta de ingestión y recuperación, control, identidad, fuente citada, efecto y punto exacto donde se cruza el límite. Para acceso directo a vectores usa `ai-embeddings`.

Base temática: material AI-300 aportado por el usuario, RAG (cap. 5) y capstone (cap. 11). Redacción original.
