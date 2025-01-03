-- +goose Up
CREATE TABLE chirps (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    body TEXT NOT NULL,
    user_id UUID NOT NULL,
    CONSTRAINT user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
-- +goose Down
DROP TABLE chirps CASCADE;