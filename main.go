package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Ethanol2/Chirpy/internal/auth"
	"github.com/Ethanol2/Chirpy/internal/database"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/subosito/gotenv"
)

// #region Structs and Global
// =====================================================================================================================================

type apiConfig struct {
	fileServerHits atomic.Int32
	Db             *database.Queries
	Platform       string
	Secret         string
	PolkaAPIKey    string
}
type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

var bad_words = [...]string{"kerfuffle", "sharbert", "fornax"}

const default_err_msg = "Something went wrong while processing the request"
const jwt_expiration_time = time.Duration(3600) * time.Second

// #region Main
// =====================================================================================================================================

func main() {

	gotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dbQueries := database.New(db)

	mux := http.NewServeMux()
	config := apiConfig{
		Db:          dbQueries,
		Platform:    os.Getenv("PLATFORM"),
		Secret:      os.Getenv("SECRET"),
		PolkaAPIKey: os.Getenv("POLKA_KEY"),
	}

	mux.Handle("/app/", http.StripPrefix("/app/", config.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	// WebHooks
	mux.HandleFunc("POST /api/polka/webhooks", config.polkaWebhookHandler)

	// Misc
	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)
	mux.HandleFunc("POST /admin/reset", config.resetHandler)
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	// Chirps
	mux.HandleFunc("GET /api/chirps", config.getChirpsHandler)
	mux.HandleFunc("POST /api/chirps", config.middlewareAuthentication(config.postChirpHandler))
	mux.HandleFunc("GET /api/chirps/{chirpID}", config.getChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", config.middlewareAuthentication(config.deleteChirpHandler))

	// Auth
	mux.HandleFunc("POST /api/users", config.createUserHandler)
	mux.HandleFunc("POST /api/login", config.loginHandler)
	mux.HandleFunc("POST /api/refresh", config.refreshHandler)
	mux.HandleFunc("POST /api/revoke", config.revokeHandler)
	mux.HandleFunc("PUT /api/users", config.middlewareAuthentication(config.putUserHandler))

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}

// #region Helpers
// =====================================================================================================================================

// Responce
func respondWithServerError(w http.ResponseWriter, err error) {
	log.Println(err)
	respondWithError(w, http.StatusInternalServerError, default_err_msg)
}
func respondWithError(w http.ResponseWriter, code int, msg string) {

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)

	w.Write([]byte(fmt.Sprintf(`{
		"error": "%s"
	}`, msg)))
}
func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)

	content, err := json.Marshal(&payload)
	if err != nil {
		log.Println("Something went wrong with json.Marshal")
		respondWithError(w, 500, default_err_msg)
		return
	}

	w.Write(content)
}
func respondWithNoContent(w http.ResponseWriter) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)

}

// Misc
func cleanMessage(msg string) string {
	words := strings.Split(msg, " ")

	for i, word := range words {
		for _, curse := range bad_words {

			if strings.ToLower(word) == curse {
				words[i] = "****"
				break
			}
		}
	}

	cleanMsg := ""
	for _, word := range words {
		cleanMsg += word + " "
	}

	return strings.TrimSpace(cleanMsg)
}
func retrieveFromHeader(w http.ResponseWriter, r *http.Request, function func(http.Header) (string, error)) string {

	key, err := function(r.Header)
	if err != nil {
		if err == auth.ErrInvalidFormat || err == auth.ErrMissingBearerText || err == auth.ErrMissingHeader || err == auth.ErrMissingAPIText {
			respondWithError(w, http.StatusUnauthorized, err.Error())
			return ""
		}
		respondWithServerError(w, err)
		return ""
	}

	return key
}
func (cfg *apiConfig) retrieveChirpWithID(w http.ResponseWriter, r *http.Request) database.Chirp {
	uuidStr := r.PathValue("chirpID")

	if len(uuidStr) == 0 {
		respondWithError(w, http.StatusBadRequest, "No chirp uuid provided")
		return database.Chirp{}
	}

	chirpId, err := uuid.Parse(uuidStr)
	if err != nil {
		log.Println(uuidStr)
		respondWithServerError(w, err)
		return database.Chirp{}
	}

	chirp, err := cfg.Db.GetChirp(r.Context(), chirpId)
	if err != nil {

		if strings.Contains(err.Error(), "no rows in result set") {
			respondWithError(w, http.StatusNotFound, "No chirp found")
			return database.Chirp{}
		}

		respondWithServerError(w, err)
	}

	return chirp
}

// Mapping
func userToUser(dbUser database.User, token, refreshToken string) User {
	return User{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  dbUser.IsChirpyRed,
	}
}
func chirpToChirp(chirp database.Chirp) Chirp {
	return Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}
}

// #region Middleware
// =====================================================================================================================================

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
func (cfg *apiConfig) middlewareAuthentication(function func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		token := retrieveFromHeader(w, r, auth.GetBearerToken)
		if token == "" {
			return
		}

		id, err := auth.ValidateJWT(token, cfg.Secret)
		if err != nil {
			log.Println(err)
			respondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		function(w, r, id)
	}
}

// #region Auth Handlers
// =====================================================================================================================================

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {

	reqBody := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	user, err := cfg.Db.GetUserByEmail(r.Context(), reqBody.Email)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	success, err := auth.CheckPasswordHash(reqBody.Password, user.HashedPassword)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	if !success {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
	}

	token, err := auth.MakeJWT(user.ID, cfg.Secret, jwt_expiration_time)
	if err != nil {
		respondWithServerError(w, err)
	}

	refreshToken := auth.MakeRefreshToken()
	_, err = cfg.Db.RegisterRefreshToken(r.Context(), database.RegisterRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Duration(60*24) * time.Hour),
	})
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	respondWithJson(w, http.StatusOK, userToUser(user, token, refreshToken))
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {

	reqBody := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	if len(reqBody.Email) == 0 || len(reqBody.Password) == 0 {
		respondWithError(w, http.StatusBadRequest, "Email and password required")
		return
	}

	hash, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	usr, err := cfg.Db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          reqBody.Email,
		ID:             uuid.New(),
		HashedPassword: hash,
	})
	if err != nil {
		if strings.Contains(err.Error(), "email") {
			log.Println(err)
			respondWithError(w, http.StatusConflict, "Email has already been used")
			return
		}

		respondWithServerError(w, err)
		return
	}

	respondWithJson(w, http.StatusCreated, userToUser(usr, "", ""))
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {

	rToken := retrieveFromHeader(w, r, auth.GetBearerToken)
	if rToken == "" {
		return
	}

	rTokenRecord, err := cfg.Db.GetRefreshTokenRecord(r.Context(), rToken)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusNotFound, "request token not found")
		return
	}

	if rTokenRecord.ExpiresAt.Before(time.Now()) {
		log.Println("Refresh token expired")
		respondWithError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}

	if rTokenRecord.RevokedAt.Valid && rTokenRecord.RevokedAt.Time.Before(time.Now()) {
		log.Println("Refresh token revoked")
		respondWithError(w, http.StatusUnauthorized, "refresh token revoked")
		return
	}

	token, err := auth.MakeJWT(rTokenRecord.UserID, cfg.Secret, jwt_expiration_time)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	respondWithJson(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{Token: token})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {

	rToken := retrieveFromHeader(w, r, auth.GetBearerToken)
	if rToken == "" {
		return
	}

	_, err := cfg.Db.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
		Token:     rToken,
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	respondWithNoContent(w)
}

func (cfg *apiConfig) putUserHandler(w http.ResponseWriter, r *http.Request, userId uuid.UUID) {

	credentials := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		respondWithServerError(w, err)
	}

	hashed, err := auth.HashPassword(credentials.Password)
	if err != nil {
		respondWithServerError(w, err)
	}

	user, err := cfg.Db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userId,
		Email:          credentials.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		respondWithServerError(w, err)
	}

	respondWithJson(w, http.StatusOK, userToUser(user, "", ""))
}

// #region Chirp Handlers
// =====================================================================================================================================

func (cfg *apiConfig) postChirpHandler(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {

	request := struct {
		Body string `json:"body"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Println("Error decoding request body:")

		respondWithServerError(w, err)

		return
	}

	charCount := len([]rune(request.Body))
	if charCount > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	chirp, err := cfg.Db.PostChirp(r.Context(), database.PostChirpParams{
		ID:     uuid.New(),
		Body:   cleanMessage(request.Body),
		UserID: userID,
	})
	if err != nil {
		log.Println(r.Body)
		respondWithServerError(w, err)
		return
	}
	respondWithJson(w, http.StatusCreated, chirpToChirp(chirp))
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request, userId uuid.UUID) {

	chirp := cfg.retrieveChirpWithID(w, r)
	if chirp.ID == uuid.Nil {
		return
	}
	if userId != chirp.UserID {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	err := cfg.Db.DeleteChirp(r.Context(), chirp.ID)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	respondWithNoContent(w)

}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {

	authorId := r.URL.Query().Get("author_id")
	var dbChirps []database.Chirp
	var err error

	if authorId == "" {

		dbChirps, err = cfg.Db.GetAllChirps(r.Context())
		if err != nil {
			respondWithServerError(w, err)
			return
		}

	} else {

		authorUUID, err := uuid.Parse(authorId)
		if err != nil {
			respondWithServerError(w, err)
			return
		}

		dbChirps, err = cfg.Db.GetUserChirps(r.Context(), authorUUID)
		if err != nil {
			respondWithServerError(w, err)
			return
		}
	}

	chirps := []Chirp{}
	for _, chirp := range dbChirps {
		chirps = append(chirps, chirpToChirp(chirp))
	}

	respondWithJson(w, http.StatusOK, chirps)

}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {

	chirp := cfg.retrieveChirpWithID(w, r)
	if chirp.ID == uuid.Nil {
		return
	}

	respondWithJson(w, http.StatusOK, chirpToChirp(chirp))
}

// #region WebHooks
// =====================================================================================================================================

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {

	key := retrieveFromHeader(w, r, auth.GetApiKey)
	if key == "" {
		return
	}

	if key != cfg.PolkaAPIKey {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rBody := struct {
		Event string `json:"event"`
		Data  struct {
			UserId uuid.UUID `json:"user_id"`
		} `json:"data"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&rBody)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	if rBody.Event != "user.upgraded" {
		respondWithNoContent(w)
		return
	}

	_, err = cfg.Db.ChangeChirpyRed(r.Context(), database.ChangeChirpyRedParams{
		IsChirpyRed: true,
		ID:          rBody.Data.UserId,
	})

	if err != nil {
		respondWithServerError(w, err)
		return
	}

	respondWithNoContent(w)

}

// #region Misc Handlers
// =====================================================================================================================================

func readinessHandler(writer http.ResponseWriter, request *http.Request) {

	writer.Header().Add("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(200)

	_, err := writer.Write([]byte("OK"))
	if err != nil {
		fmt.Println(err)
	}

}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)

	_, err := w.Write([]byte(fmt.Sprintf(`<html>
	<body>
	  <h1>Welcome, Chirpy Admin</h1>
	  <p>Chirpy has been visited %d times!</p>
	</body>
  </html>`, cfg.fileServerHits.Load())))
	if err != nil {
		fmt.Println(err)
	}
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {

	if cfg.Platform != "dev" {
		respondWithError(w, http.StatusForbidden, default_err_msg)
		return
	}

	err := cfg.Db.NukeUsers(r.Context())
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)

	_, err = w.Write([]byte("OK"))
	if err != nil {
		fmt.Println(err)
	}

	cfg.fileServerHits.Store(0)

}
