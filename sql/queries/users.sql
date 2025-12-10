-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    $1, NOW(), NOW(), $2
)
RETURNING *;

-- name: NukeUsers :exec
DELETE FROM users;