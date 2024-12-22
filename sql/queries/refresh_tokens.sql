-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, expires_at, revoked_at)
VALUES ($1, $2, NOW() + interval '60 days', NULL);
-- name: GetUserByRefreshToken :one
SELECT *
FROM refresh_tokens
WHERE token = $1;
-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1;