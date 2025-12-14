-- name: PostChirp :one
INSERT INTO chirps(id, created_at, updated_at, body, user_id)
VALUES ($1, NOW(), NOW(), $2, $3)
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirps ORDER BY created_at ASC;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id = $1;