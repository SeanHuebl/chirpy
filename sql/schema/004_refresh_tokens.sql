-- +goose Up
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY Key,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id UUID NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    CONSTRAINT user_fk FOREIGN Key (user_id) REFERENCES users (id) ON DELETE CASCADE
);
-- +goose Down
DROP TABLE refresh_tokens CASCADE;