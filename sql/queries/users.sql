-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    $1, NOW(), NOW(), $2, $3
)
RETURNING *;

-- name: NukeUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email=$1;

-- name: UpdateUser :one
UPDATE users SET email=$1, hashed_password=$2, updated_at=NOW() WHERE id=$3
RETURNING *;

-- name: ChangeChirpyRed :one
UPDATE users SET is_chirpy_red=$1, updated_at=NOW() WHERE id=$2
RETURNING *;

-- Auth ----------------------------------------------------------------------

-- name: RegisterRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1, NOW(), NOW(), $2, $3, NULL
)
RETURNING *;

-- name: GetRefreshTokenRecord :one
SELECT * FROM refresh_tokens WHERE token = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens SET revoked_at = $2, updated_at = NOW() WHERE token = $1
RETURNING *;