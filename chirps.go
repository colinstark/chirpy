package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func clean(body string) string {
	naughty_list := []string{"Kerfuffle", "Sharbert", "Fornax"}
	for _, word := range naughty_list {
		replacer := strings.NewReplacer(word, "****", strings.ToLower(word), "****", strings.ToUpper(word), "****")
		body = replacer.Replace(body)
	}

	return body
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body   string `json:"body"`
		UserID string `json:"user_id"`
	}

	type errorReturn struct {
		Error string `json:"error"`
	}

	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid Token", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	params := parameters{}
	err = json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(params.Body) > 140 {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(errorReturn{
			Error: "Chirp is too long",
		})
		return
	}

	chirpObj, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   clean(params.Body),
		UserID: userID,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(chirp{
		ID:        chirpObj.ID,
		Body:      chirpObj.Body,
		CreatedAt: chirpObj.CreatedAt,
		UpdatedAt: chirpObj.UpdatedAt,
		UserID:    chirpObj.UserID,
	})

}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	chirpObj, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(chirp{
		ID:        chirpObj.ID,
		Body:      chirpObj.Body,
		CreatedAt: chirpObj.CreatedAt,
		UpdatedAt: chirpObj.UpdatedAt,
		UserID:    chirpObj.UserID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	chirpObj, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Failed to get bearer token from header", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if chirpObj.UserID != userID {
		http.Error(w, "Forbidden: Not the author", http.StatusForbidden)
		return
	}

	cfg.db.DeleteChirp(r.Context(), chirpObj.ID)

	w.WriteHeader(204)
}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	authorIDString := r.URL.Query().Get("author_id")
	sortDirectionString := r.URL.Query().Get("sort")

	var chirps []database.Chirp
	var err error
	if authorIDString != "" {
		authorID, err := uuid.Parse(authorIDString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		chirps, err = cfg.db.GetAllChirpsFromAuthor(r.Context(), authorID)
	} else {
		chirps, err = cfg.db.GetAllChirps(r.Context())
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	if sortDirectionString == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].CreatedAt.After(chirps[j].CreatedAt)  })
	}

	apiChirps := dbChirpsToAPIChirps(chirps)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	err = json.NewEncoder(w).Encode(apiChirps)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func dbChirpsToAPIChirps(dbChirps []database.Chirp) []chirp {
	apiChirps := make([]chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		apiChirps[i] = chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
	}
	return apiChirps
}
