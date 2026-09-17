-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS swarm_agent_configs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  agent_id VARCHAR(64) NOT NULL,
  api_provider VARCHAR(64) NOT NULL,
  api_key TEXT NOT NULL,
  api_endpoint TEXT NOT NULL,
  model VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'unconfigured',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_swarm_agent_configs_user_id ON swarm_agent_configs(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS swarm_agent_configs;

-- +goose StatementEnd
