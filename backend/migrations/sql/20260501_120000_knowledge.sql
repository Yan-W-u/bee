-- +goose Up
-- +goose StatementBegin

INSERT INTO privileges (role_id, name) VALUES
  (1, 'knowledge.admin'),
  (1, 'knowledge.view'),
  (1, 'knowledge.create'),
  (1, 'knowledge.edit'),
  (1, 'knowledge.delete'),
  (1, 'knowledge.search'),
  (1, 'knowledge.subscribe'),
  (2, 'knowledge.view'),
  (2, 'knowledge.create'),
  (2, 'knowledge.edit'),
  (2, 'knowledge.delete'),
  (2, 'knowledge.search'),
  (2, 'knowledge.subscribe')
  ON CONFLICT DO NOTHING;

-- Try to enable the vector extension. Portable/offline packages may ship without
-- pgvector; in that case knowledge-base features are disabled but the rest of the
-- application must still start. The DO block catches the missing-extension error
-- so the migration succeeds regardless.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgvector extension not available, knowledge base features will be disabled: %', SQLERRM;
END;
$$;

-- Only create the langchain vector tables when the extension is actually present.
-- When pgvector is missing these tables are skipped entirely.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
    -- Logical namespace for embeddings.
    -- DDL kept identical to what langchaingo's createCollectionTableIfNotExists generates
    -- so IF NOT EXISTS is a true no-op when the table already exists.
    CREATE TABLE IF NOT EXISTS langchain_pg_collection (
      name      varchar,
      cmetadata json,
      "uuid"    uuid NOT NULL,
      UNIQUE (name),
      PRIMARY KEY ("uuid")
    );

    -- Physical storage for chunked text, vector embeddings and per-document metadata.
    -- DDL kept identical to what langchaingo's createEmbeddingTableIfNotExists generates.
    CREATE TABLE IF NOT EXISTS langchain_pg_embedding (
      collection_id uuid,
      embedding     vector,
      document      varchar,
      cmetadata     json,
      "uuid"        uuid NOT NULL,
      CONSTRAINT langchain_pg_embedding_collection_id_fkey
        FOREIGN KEY (collection_id)
        REFERENCES langchain_pg_collection ("uuid") ON DELETE CASCADE,
      PRIMARY KEY ("uuid")
    );

    CREATE INDEX IF NOT EXISTS langchain_pg_embedding_collection_id
      ON langchain_pg_embedding (collection_id);

    -- Step 1: Backfill user_id from flows for documents whose flow still exists.
    -- Documents whose flow_id has no matching row are left with user_id NULL.
    UPDATE langchain_pg_embedding e
    SET cmetadata = (e.cmetadata::jsonb || jsonb_build_object('user_id', f.user_id))::json
    FROM langchain_pg_collection c, flows f
    WHERE e.collection_id = c.uuid
      AND c.name = 'langchain'
      AND (e.cmetadata ->> 'flow_id') IS NOT NULL
      AND (e.cmetadata ->> 'user_id') IS NULL
      AND f.id = (e.cmetadata ->> 'flow_id')::bigint;

    -- Step 2: For any remaining documents still missing user_id (no flow_id, deleted
    -- flow, or manually created before user tracking), default to user_id = 1.
    UPDATE langchain_pg_embedding e
    SET cmetadata = (e.cmetadata::jsonb || jsonb_build_object('user_id', 1))::json
    FROM langchain_pg_collection c
    WHERE e.collection_id = c.uuid
      AND c.name = 'langchain'
      AND (e.cmetadata ->> 'user_id') IS NULL;

    -- Purge accumulated memory documents from the vector store that belong to flows
    -- which have already been soft-deleted (deleted_at IS NOT NULL) or no longer exist
    -- in the flows table at all.
    DELETE FROM langchain_pg_embedding e
    USING langchain_pg_collection c
    WHERE e.collection_id = c.uuid
      AND c.name = 'langchain'
      AND COALESCE(e.cmetadata ->> 'doc_type', '') = 'memory'
      AND (e.cmetadata ->> 'flow_id') IS NOT NULL
      AND NOT EXISTS (
        SELECT 1
        FROM flows f
        WHERE f.id = (e.cmetadata ->> 'flow_id')::bigint
          AND f.deleted_at IS NULL
      );
  END IF;
END;
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM privileges WHERE name LIKE 'knowledge.%';

-- The langchain tables are intentionally NOT dropped in Down:
-- they hold production knowledge data managed by the pgvector store.

-- The deleted memory documents cannot be recovered (the embedding data is gone).
-- Down migration is intentionally a no-op.

-- +goose StatementEnd
