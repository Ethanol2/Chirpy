# Chirpy
Boot.dev guided project. In essence, a very basic version of Twitter

# Chirpy API Reference

This document provides a comprehensive reference for the Chirpy API endpoints. Chirpy is a simple social media platform where users can post "chirps" (short messages).

## Authentication

Some endpoints require authentication using JWT tokens. Include the token in the `Authorization` header as `Bearer <token>`.

Refresh tokens are used for obtaining new JWTs.

## Endpoints

### Health Check

#### GET /api/healthz
Checks if the server is ready.

**Response:**
- Status: 200 OK
- Body: `OK`

### Admin Endpoints

#### GET /admin/metrics
Returns metrics about the application.

**Response:**
- Status: 200 OK
- Content-Type: text/html
- Body: HTML page with visit count.

#### POST /admin/reset
Resets the database and metrics. Only available in development mode.

**Response:**
- Status: 200 OK
- Body: `OK`

### User Management

#### POST /api/users
Creates a new user.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- Status: 201 Created
- Body:
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "email": "string",
  "is_chirpy_red": false
}
```

#### POST /api/login
Logs in a user.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- Status: 200 OK
- Body:
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "email": "string",
  "token": "jwt_token",
  "refresh_token": "refresh_token",
  "is_chirpy_red": false
}
```

#### PUT /api/users
Updates user information. Requires authentication.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- Status: 200 OK
- Body:
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "email": "string",
  "is_chirpy_red": false
}
```

### Token Management

#### POST /api/refresh
Refreshes the JWT token using a refresh token.

**Headers:**
- Authorization: Bearer <refresh_token>

**Response:**
- Status: 200 OK
- Body:
```json
{
  "token": "new_jwt_token"
}
```

#### POST /api/revoke
Revokes a refresh token.

**Headers:**
- Authorization: Bearer <refresh_token>

**Response:**
- Status: 204 No Content

### Chirps

#### GET /api/chirps
Retrieves all chirps or chirps by a specific author.

**Query Parameters:**
- `author_id` (optional): UUID of the author

**Response:**
- Status: 200 OK
- Body: Array of chirps
```json
[
  {
    "id": "uuid",
    "created_at": "timestamp",
    "updated_at": "timestamp",
    "body": "string",
    "user_id": "uuid"
  }
]
```

#### POST /api/chirps
Creates a new chirp. Requires authentication. Body is cleaned of bad words and limited to 140 characters.

**Request Body:**
```json
{
  "body": "string"
}
```

**Response:**
- Status: 201 Created
- Body:
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "body": "string",
  "user_id": "uuid"
}
```

#### GET /api/chirps/{chirpID}
Retrieves a single chirp by ID.

**Path Parameters:**
- `chirpID`: UUID of the chirp

**Response:**
- Status: 200 OK
- Body:
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "body": "string",
  "user_id": "uuid"
}
```

#### DELETE /api/chirps/{chirpID}
Deletes a chirp. Requires authentication and ownership.

**Path Parameters:**
- `chirpID`: UUID of the chirp

**Response:**
- Status: 204 No Content

### Webhooks

#### POST /api/polka/webhooks
Handles webhooks from Polka for upgrading users to Chirpy Red.

**Headers:**
- Authorization: ApiKey <api_key>

**Request Body:**
```json
{
  "event": "user.upgraded",
  "data": {
    "user_id": "uuid"
  }
}
```

**Response:**
- Status: 204 No Content