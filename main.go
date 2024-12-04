package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/seanhuebl/chirpy/internal/database"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
}

type parameters struct {
	Body string `json:"body"`
}

type returnError struct {
	Error string `json:"error"`
}

type returnCleaned struct {
	CleanedBody string `json:"cleaned_body"`
}

func (cfg *apiConfig) middlewareMetricsIncrease(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func handlerHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

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

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileServerHits.Store(0)
}

func jsonResponse(w http.ResponseWriter, httpStatus int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	w.Write(data)
}

func errorResponse(w http.ResponseWriter, httpStatus int, msg string) {
	respBody := returnError{
		Error: msg,
	}
	data, err := json.Marshal(respBody)
	if err != nil {
		// Log the error, then adjust your response
		log.Printf("Error marshaling JSON: %v", err)
		// Provide a fallback response as a byte slice
		data = []byte(`{"error":"internal server error"}`)
	}
	jsonResponse(w, httpStatus, data)
}

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

func handlerValidate(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "error decoding params")
		return
	}
	if len(params.Body) > 140 {
		errorResponse(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	var data []byte
	body := badWordCheck(&params)

	respBodyCleaned := returnCleaned{
		CleanedBody: body,
	}
	data, err = json.Marshal(respBodyCleaned)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "error marshaling data")
		return
	}

	jsonResponse(w, http.StatusOK, data)
}

func main() {
	sMux := http.NewServeMux()
	var state apiConfig
	server := http.Server{
		Handler: sMux,
		Addr:    ":8080",
	}
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
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
	sMux.HandleFunc("POST /api/validate_chirp", handlerValidate)
	sMux.Handle("/app/", state.middlewareMetricsIncrease(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	server.ListenAndServe()
}
