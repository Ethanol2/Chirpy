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

type apiConfig struct {
	fileServerHits atomic.Int32
	Db             *database.Queries
	Platform       string
	Secret         string
}
type Response struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token,omitempty"`
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

// #region Main

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
		Db:       dbQueries,
		Platform: os.Getenv("PLATFORM"),
		Secret:   os.Getenv("SECRET"),
	}

	mux.Handle("/app/", http.StripPrefix("/app/", config.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)
	mux.HandleFunc("POST /admin/reset", config.resetHandler)
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	mux.HandleFunc("GET /api/chirps", config.getChirpsHandler)
	mux.HandleFunc("POST /api/chirps", config.middlewareAuthentication(config.postChirpHandler))
	mux.HandleFunc("GET /api/chirps/{chirpID}", config.getChirpHandler)

	mux.HandleFunc("POST /api/users", config.createUserHandler)
	mux.HandleFunc("POST /api/login", config.loginHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}

// #region Helpers

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
func userToUser(dbUser database.User, token string) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
		Token:     token,
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

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
func (cfg *apiConfig) middlewareAuthentication(function func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithServerError(w, err)
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

// #region Handlers

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

	// response := Response{
	// 	Message: "Created",
	// 	Data:    userToUser(usr),
	// }
	respondWithJson(w, http.StatusCreated, userToUser(usr, ""))
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {

	dbChirps, err := cfg.Db.GetAllChirps(r.Context())
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	chirps := []Chirp{}
	for _, chirp := range dbChirps {
		chirps = append(chirps, chirpToChirp(chirp))
	}

	respondWithJson(w, http.StatusOK, chirps)

}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {

	uuidStr := r.PathValue("chirpID")

	if len(uuidStr) == 0 {
		respondWithError(w, http.StatusBadRequest, "No chirp uuid provided")
		return
	}

	chirpId, err := uuid.Parse(uuidStr)
	if err != nil {
		log.Println(uuidStr)
		respondWithServerError(w, err)
		return
	}

	chirp, err := cfg.Db.GetChirp(r.Context(), chirpId)
	if err != nil {

		if strings.Contains(err.Error(), "no rows in result set") {
			respondWithError(w, http.StatusNotFound, "No chirp found")
			return
		}

		respondWithServerError(w, err)
	}

	respondWithJson(w, http.StatusOK, chirpToChirp(chirp))
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {

	reqBody := struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}{
		ExpiresInSeconds: 3600,
	}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		respondWithServerError(w, err)
		return
	}

	if reqBody.ExpiresInSeconds > 3600 || reqBody.ExpiresInSeconds < 0 {
		reqBody.ExpiresInSeconds = 3600
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

	token, err := auth.MakeJWT(user.ID, cfg.Secret, time.Duration(reqBody.ExpiresInSeconds)*time.Second)
	if err != nil {
		respondWithServerError(w, err)
	}

	respondWithJson(w, http.StatusOK, userToUser(user, token))
}
