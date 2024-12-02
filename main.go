package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

type parameters struct {
	Body string `json:"body"`
}

type returnError struct {
	Error string `json:"error"`
}

type returnValid struct {
	Valid bool `json:"valid"`
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

func badWordCheck(p *parameters) (string, bool) {
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
		return p.Body, replaced
	}
	cleanedBody := strings.Join(bodySplit, " ")
	return cleanedBody, true
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
	body, isCleaned := badWordCheck(&params)
	if isCleaned {
		respBodyCleaned := returnCleaned{
			CleanedBody: body,
		}
		data, err = json.Marshal(respBodyCleaned)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "error marshaling data")
			return
		}
	} else {
		respBodyValid := returnValid{
			Valid: true,
		}
		data, err = json.Marshal(respBodyValid)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "error marshaling data")
			return
		}
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
	sMux.HandleFunc("GET /api/healthz", handlerHealthz)
	sMux.HandleFunc("GET /admin/metrics", state.handlerMetrics)
	sMux.HandleFunc("POST /admin/reset", state.handlerReset)
	sMux.HandleFunc("POST /api/validate_chirp", handlerValidate)
	sMux.Handle("/app/", state.middlewareMetricsIncrease(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	server.ListenAndServe()
}
