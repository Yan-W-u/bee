-- +goose Up
-- +goose StatementBegin

-- Reset default local accounts to simple credentials for demo/evaluation use.
-- These are intentionally weak and must be changed in production.

-- Rename any old default admin email to the simple address and update its
-- password. This handles databases created before the credential change.
UPDATE users
SET mail = 'admin@bee.com',
    name = 'admin',
    password = '$2a$10$UlTbft54Oh1wuPRPYKPGOOpdWbkiTS63/SZgFkmE2FG7yCLrIfY2K',
    password_change_required = false,
    status = 'active'
WHERE mail IN ('admin@pentagi.com', 'admin@p.com') AND type = 'local';

-- Ensure the admin account has the new simple password (idempotent).
UPDATE users
SET password = '$2a$10$UlTbft54Oh1wuPRPYKPGOOpdWbkiTS63/SZgFkmE2FG7yCLrIfY2K',
    password_change_required = false,
    status = 'active'
WHERE mail = 'admin@bee.com' AND type = 'local';

-- If no admin@bee.com account exists yet, create it with the simple password.
INSERT INTO users (mail, name, password, status, role_id, password_change_required)
SELECT 'admin@bee.com',
       'admin',
       '$2a$10$UlTbft54Oh1wuPRPYKPGOOpdWbkiTS63/SZgFkmE2FG7yCLrIfY2K',
       'active',
       1,
       false
WHERE NOT EXISTS (SELECT 1 FROM users WHERE mail = 'admin@bee.com' AND type = 'local');

-- Create the standard employee account if it does not exist yet.
INSERT INTO users (mail, name, password, status, role_id, password_change_required)
SELECT 'user@bee.com',
       'user',
       '$2a$10$UlTbft54Oh1wuPRPYKPGOOpdWbkiTS63/SZgFkmE2FG7yCLrIfY2K',
       'active',
       2,
       false
WHERE NOT EXISTS (SELECT 1 FROM users WHERE mail = 'user@bee.com' AND type = 'local');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Passwords cannot be reverted; Down is intentionally a no-op.
-- +goose StatementEnd
