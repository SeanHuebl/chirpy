// Package main initializes and runs the Chirpy web application,
// handling user management, chirp interactions, and administration tasks.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/seanhuebl/chirpy/internal/auth"
	"github.com/seanhuebl/chirpy/internal/database"
)

// apiConfig contains configuration parameters for the API, including the database queries,
// JWT secret, platform type, API key, and file server hit counter.
type apiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	secretString   string
	apiKey         string
}

// parameters defines the structure for request payloads used in various API endpoints.
type parameters struct {
	Body     string `json:"body"`
	Email    string `json:"email"`
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

// returnError represents the structure of error responses returned by the API.
type returnError struct {
	Error string `json:"error"`
}

// user represents a Chirpy user with associated data, including ID, email, tokens,
// and subscription status.
type user struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

// chirp represents a user's chirp (post) in the Chirpy platform.
type chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

// webhook represents the structure of incoming webhook payloads.
type webhook struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

// main initializes the server, loads environment variables, and sets up routes for the application.
func main() {
	godotenv.Load()
	sMux := http.NewServeMux()
	var state apiConfig
	server := http.Server{
		Handler: sMux,
		Addr:    ":8080",
	}
	dbURL := os.Getenv("DB_URL")
	state.platform = os.Getenv("PLATFORM")
	state.secretString = os.Getenv("JWT_SECRET")
	state.apiKey = os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dbQueries := database.New(db)
	state.dbQueries = dbQueries

	sMux.HandleFunc("GET /api/healthz", handlerHealthz)
	sMux.HandleFunc("GET /admin/metrics", state.handlerMetrics)
	sMux.HandleFunc("POST /admin/reset", state.handlerReset)
	sMux.HandleFunc("POST /api/chirps", state.handlerChirps)
	sMux.HandleFunc("POST /api/users", state.handlerUsers)
	sMux.HandleFunc("PUT /api/users", state.handlerUpdateUser)
	sMux.HandleFunc("GET /api/chirps", state.handlerGetAllChirps)
	sMux.HandleFunc("GET /api/chirps/{chirpID}", state.handlerGetChirp)
	sMux.HandleFunc("DELETE /api/chirps/{chirpID}", state.handlerDeleteChirp)
	sMux.HandleFunc("POST /api/login", state.handlerLogin)
	sMux.HandleFunc("POST /api/refresh", state.HandlerRefresh)
	sMux.HandleFunc("POST /api/revoke", state.handlerRevoke)
	sMux.HandleFunc("POST /api/polka/webhooks", state.handlerWebhooks)
	sMux.Handle("/app/", state.middlewareMetricsIncrease(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	server.ListenAndServe()
}

// middlewareMetricsIncrease increments the file server hit counter for each incoming request.
func (cfg *apiConfig) middlewareMetricsIncrease(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// handlerHealthz responds to health check requests, returning "OK" if the server is healthy.
func handlerHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handlerMetrics displays the number of file server hits as an HTML page.
func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	val := cfg.fileServerHits.Load()
	tmpl := `
	<!DOCTYPE html>
	<html>
	  <body>
	    <h1>Welcome, Chirpy Admin</h1>
	    <p>Chirpy has been visited {{.}} times!</p>
	  </body>
	</html>`
	t, err := template.New("webpage").Parse(tmpl)
	if err != nil {
		http.Error(w, "error parsing template", http.StatusInternalServerError)
	}
	t.Execute(w, val)
}

// handlerReset resets the database and file server hit counter.
// Accessible only on the development platform.
func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		errorResponse(w, http.StatusForbidden, "access forbidden")
	}
	err := cfg.dbQueries.Reset(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "error resetting users table")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileServerHits.Store(0)
}

// jsonResponse sends a JSON-encoded response with the specified HTTP status code.
func jsonResponse(w http.ResponseWriter, httpStatus int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	w.Write(data)
}

// errorResponse constructs and sends a JSON-encoded error response.
func errorResponse(w http.ResponseWriter, httpStatus int, msg string) {
	respBody := returnError{
		Error: msg,
	}
	data, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		data = []byte(`{"error":"internal server error"}`)
	}
	jsonResponse(w, httpStatus, data)
}

// badWordCheck filters and censors predefined offensive words in the chirp body.
func badWordCheck(p *parameters) string {
	substrings := []string{"kerfuffle", "sharbert", "fornax"}
	replacement := "****"
	replaced := false
	bodySplit := strings.Split(p.Body, " ")
	for i, str := range bodySplit {
		for _, sub := range substrings {
			if strings.ToLower(str) == sub {
				bodySplit[i] = replacement
				replaced = true
			}
		}
	}
	if !replaced {
		return p.Body
	}
	cleanedBody := strings.Join(bodySplit, " ")
	return cleanedBody
}

// handlerChirps processes new chirp creation, ensuring valid body length and filtering bad words.
func (cfg *apiConfig) handlerChirps(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secretString)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}

	if len(params.Body) > 140 {
		errorResponse(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleanedBody := badWordCheck(&params)
	dbChirp, err := cfg.dbQueries.CreateChirp(context.Background(), database.CreateChirpParams{Body: cleanedBody, UserID: userID})
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	var chirp chirp
	err = copier.Copy(&chirp, &dbChirp)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	data, err := json.Marshal(chirp)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}

	jsonResponse(w, http.StatusCreated, data)
}

// handlerGetAllChirps retrieves and returns all chirps, optionally filtered by author and sorted.
func (cfg *apiConfig) handlerGetAllChirps(w http.ResponseWriter, r *http.Request) {
	author := r.URL.Query().Get("author_id")
	sort := true
	s := r.URL.Query().Get("sort")
	if s == "desc" {
		sort = false
	}
	var dbChirps []database.Chirp
	if author == "" {
		var err error
		if sort {
			dbChirps, err = cfg.dbQueries.GetChirps(context.Background())
			if err != nil {
				errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
				return
			}
		} else {
			dbChirps, err = cfg.dbQueries.GetChirpsDesc(context.Background())
			if err != nil {
				errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
				return
			}
		}
	} else {
		userID, err := uuid.Parse(author)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
			return
		}
		if sort {
			dbChirps, err = cfg.dbQueries.GetUserChirps(context.Background(), userID)
			if err != nil {
				errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
				return
			}
		} else {
			dbChirps, err = cfg.dbQueries.GetUserChirpsDesc(context.Background(), userID)
			if err != nil {
				errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
				return
			}
		}
	}

	var chirps []chirp

	for _, dbChirp := range dbChirps {
		var c chirp
		err := copier.Copy(&c, &dbChirp)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
			return
		}
		chirps = append(chirps, c)
	}
	data, err := json.Marshal(chirps)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusOK, data)
}

// handlerGetChirp retrieves and returns a specific chirp by ID.
func (cfg *apiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.URL.Query().Get("chirpID"))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	dbChirp, err := cfg.dbQueries.GetChirp(context.Background(), chirpID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
		return
	}
	var chirp chirp
	err = copier.Copy(&chirp, dbChirp)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	data, err := json.Marshal(chirp)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusOK, data)
}

// handlerDeleteChirp deletes a specific chirp, ensuring the user is authorized to do so.
func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		errorResponse(w, http.StatusUnauthorized, "unauthorized request received")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secretString)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	chirpID, err := uuid.Parse(r.URL.Query().Get("chirpID"))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, fmt.Sprint(err))
		return
	}
	chirpData, err := cfg.dbQueries.GetChirp(context.Background(), chirpID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
		return
	}
	if chirpData.UserID != userID {
		errorResponse(w, http.StatusForbidden, "access denied")
		return
	}
	err = cfg.dbQueries.DeleteChirp(context.Background(), chirpID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlerUsers creates a new user with a hashed password.
func (cfg *apiConfig) handlerUsers(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}

	hashedPwd, err := auth.HashPassword(params.Password)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	dbUser, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPwd})
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	var user user
	err = copier.Copy(&user, &dbUser)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	data, err := json.Marshal(user)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusCreated, data)
}

// handlerUpdateUser updates a user's email and password.
func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		errorResponse(w, http.StatusUnauthorized, "unauthorized request received")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secretString)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	if params.Email == "" || params.Password == "" {
		errorResponse(w, http.StatusBadRequest, "must contain updated email and password")
		return
	}
	pwHash, err := auth.HashPassword(params.Password)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	userDb, err := cfg.dbQueries.UpdateUser(context.Background(), database.UpdateUserParams{Email: params.Email, HashedPassword: pwHash, ID: userID})
	var user user
	copier.Copy(&user, &userDb)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	data, err := json.Marshal(user)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusOK, data)
}

// handlerWebhooks handles incoming webhook events for user upgrades.
// It verifies the API key, decodes the webhook payload, and upgrades the user if applicable.
func (cfg *apiConfig) handlerWebhooks(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		errorResponse(w, http.StatusUnauthorized, "unauthorized request received")
		return
	}
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, fmt.Sprint(err))
		return
	}
	if apiKey != cfg.apiKey {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	decoder := json.NewDecoder(r.Body)
	webhook := webhook{}
	err = decoder.Decode(&webhook)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, fmt.Sprint(err))
		return
	}
	if webhook.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	userID, err := uuid.Parse(webhook.Data.UserID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	err = cfg.dbQueries.UpgradeUser(context.Background(), userID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprint(err))
	}
	w.WriteHeader(http.StatusNoContent)
}

// ValidatePassword validates the given password against specific security criteria.
// The password must meet the following requirements:
// - Minimum length of 8 characters
// - Contains at least one uppercase letter
// - Contains at least one lowercase letter
// - Contains at least one digit
// - Contains at least one special character
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if matched, _ := regexp.MatchString(`\d`, password); !matched {
		return fmt.Errorf("password must contain at least one digit")
	}
	if matched, _ := regexp.MatchString(`[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':"\\|,.<>\/?]`, password); !matched {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

// handlerLogin processes user login requests.
// It validates the user's email and password, generates a JWT, and returns the user details.
func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	dbUser, err := cfg.dbQueries.GetUserByEmail(context.Background(), params.Email)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}
	err = auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	var user user
	err = copier.Copy(&user, &dbUser)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	token, err := auth.MakeJWT(user.ID, cfg.secretString, time.Hour)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	user.Token = token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	err = cfg.dbQueries.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{Token: refreshToken, UserID: user.ID})
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	user.RefreshToken = refreshToken
	data, err := json.Marshal(user)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusOK, data)
}

// HandlerRefresh handles refresh token requests.
// It validates the provided refresh token, generates a new JWT, and returns it in the response.
func (cfg *apiConfig) HandlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	dbUser, err := cfg.dbQueries.GetUserByRefreshToken(context.Background(), refreshToken)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, "token not found")
		return
	}
	if dbUser.RevokedAt.Valid && dbUser.RevokedAt.Time.Before(time.Now()) {
		errorResponse(w, http.StatusUnauthorized, "expired token")
		return
	}
	jwt, err := auth.MakeJWT(dbUser.UserID, cfg.secretString, time.Hour)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
	}
	tokenJSON := map[string]interface{}{
		"token": jwt,
	}
	data, err := json.Marshal(tokenJSON)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	jsonResponse(w, http.StatusOK, data)
}

// handlerRevoke revokes a user's refresh token.
// It removes the token from the database to prevent further use.
func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
		return
	}
	err = cfg.dbQueries.RevokeRefreshToken(context.Background(), refreshToken)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, fmt.Sprint(err))
	}
	jsonResponse(w, http.StatusNoContent, nil)
}
