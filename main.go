package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkaKey       string
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	secret := os.Getenv("SECRET")
	db, err := sql.Open("postgres", dbURL)

	apiCfg := apiConfig{
		db:       database.New(db),
		platform: os.Getenv("PLATFORM"),
		secret:   secret,
		polkaKey: os.Getenv("POLKA_KEY"),
	}

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("./app/"))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fs)))
	mux.HandleFunc("GET /admin/metrics", apiCfg.countHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("/api/fail", notFoundHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	// mux.HandleFunc("PUT /api/users/{userID}", apiCfg.updateUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUser)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleWebhooks)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) countHandler(w http.ResponseWriter, r *http.Request) {
	count := cfg.fileserverHits.Load()
	html := "<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>"
	formattedHTML := fmt.Sprintf(html, count)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(formattedHTML))
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "404 not found", 404)
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1) // runs for each request
		next.ServeHTTP(w, r)      // then calls the next handler
	})
}

func (cfg *apiConfig) count(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Hits: %v", cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)

	if cfg.platform != "dev" {
		http.Error(w, "", 403)
		return
	}

	// Execute the DeleteAllUsers query
	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Couldn't delete users", 500)
		return
	}
	err = cfg.db.DeleteAllChirps(r.Context())
	if err != nil {
		http.Error(w, "Couldn't delete chirps", 500)
		return
	}
	err = cfg.db.DeleteAllRefreshTokens(r.Context())
	if err != nil {
		http.Error(w, "Couldn't delete refresh tokens", 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("Reset everything")))

}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type loginParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type userResponse struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}

	params := loginParams{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword.String)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized) // Generic error for security
		return
	}

	expiryTime := time.Minute * 60

	token, err := auth.MakeJWT(user.ID, cfg.secret, expiryTime)
	if err != nil {
		http.Error(w, "Something wrong with the token", http.StatusUnauthorized)
		return
	}
	refresh_token_string, err := auth.MakeRefreshToken()

	refresh_token, err := cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:  refresh_token_string,
		UserID: user.ID,
	})
	if err != nil {
		http.Error(w, "Something wrong with creating the refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	err = json.NewEncoder(w).Encode(userResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refresh_token.Token,
		IsChirpyRed:  user.IsChirpyRed,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	type refreshResponse struct {
		Token string `json:"token"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Failed to get bearer token from header", http.StatusUnauthorized)
		return
	}

	refresh_entry, err := cfg.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		http.Error(w, "Failed to get refresh token", http.StatusUnauthorized)
		return
	}

	if refresh_entry.RevokedAt.Valid {
		http.Error(w, "Refresh token revoked", http.StatusUnauthorized)
		return

	} else {
		user_id, err := cfg.db.GetRefreshTokenUser(r.Context(), token)
		if err != nil {
			http.Error(w, "Failed to get refresh token", http.StatusUnauthorized)
			return
		}

		expiryTime := time.Minute * 60
		jwt, err := auth.MakeJWT(user_id, cfg.secret, expiryTime)
		if err != nil {
			http.Error(w, "Failed to get refresh token", http.StatusUnauthorized)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		err = json.NewEncoder(w).Encode(refreshResponse{
			Token: jwt,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	}

}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Failed to get bearer token from header", http.StatusUnauthorized)
		return
	}

	refresh_entry, err := cfg.db.RevokeToken(r.Context(), token)
	if refresh_entry.RevokedAt.Valid {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(204)
		return
	} else {
		http.Error(w, "Refresh token Revocation failed", http.StatusUnauthorized)
		return
	}

}
