-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS provider_presets (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  name VARCHAR(128) NOT NULL,
  api_provider VARCHAR(64) NOT NULL,
  api_key TEXT NOT NULL,
  api_endpoint TEXT NOT NULL,
  model VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_provider_presets_user_id ON provider_presets(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS provider_presets;

-- +goose StatementEnd
