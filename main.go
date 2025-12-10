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
	}

	mux.Handle("/app/", http.StripPrefix("/app/", config.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	mux.HandleFunc("GET /admin/metrics", config.metricsHandler)
	mux.HandleFunc("POST /admin/reset", config.resetHandler)

	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	mux.HandleFunc("POST /api/users", config.createUserHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}

// #region Helpers

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
func userToUser(dbUser database.User) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
}

// #region Middleware

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
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
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, default_err_msg)
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

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {

	request := struct{ Body string }{}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("Error decoding request body: %s", err)

		respondWithError(w, 500, default_err_msg)

		return
	}

	response := struct {
		CleanedBody string `json:"cleaned_body,omitempty"`
		Error       string `json:"error,omitempty"`
		Valid       bool   `json:"valid,omitempty"`
	}{}

	charCount := len([]rune(request.Body))
	if charCount > 140 {
		response.Error = "Chirp is too long"
		response.Valid = false
		respondWithJson(w, 400, response)
		return

	}

	response.CleanedBody = cleanMessage(request.Body)
	response.Valid = true
	respondWithJson(w, 200, response)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {

	reqBody := User{}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, default_err_msg)
		return
	}

	usr, err := cfg.Db.CreateUser(r.Context(), database.CreateUserParams{
		Email: reqBody.Email,
		ID:    uuid.New(),
	})
	if err != nil {

		log.Println(err)

		if strings.Contains(err.Error(), "email") {
			respondWithError(w, http.StatusConflict, "Email has already been used")
			return
		}

		respondWithError(w, http.StatusInternalServerError, default_err_msg)
		return
	}

	// response := Response{
	// 	Message: "Created",
	// 	Data:    userToUser(usr),
	// }
	respondWithJson(w, http.StatusCreated, userToUser(usr))
}
