package main

import (
	"chirpy/internal/auth"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

type webhookParams struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

func (cfg *apiConfig) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	params := webhookParams{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if apiKey != cfg.polkaKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if params.Event == "user.upgraded" {

		userID, err := uuid.Parse(params.Data.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err = cfg.db.GetUserByID(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		_, err = cfg.db.ActivateRedForUser(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(204)
}
