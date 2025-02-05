package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
)

type Health struct{}

func NewHealth() *Health {
	return &Health{}
}

func (h *Health) Status(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	now := time.Now().UTC()

	h.status(w, r, p, now)
}

func (h *Health) status(w http.ResponseWriter, r *http.Request, _ httprouter.Params, now time.Time) {
	result := &struct {
		Status string    `json:"status"`
		Time   time.Time `json:"time"`
	}{
		Status: "ok",
		Time:   now,
	}

	_ = respondWithDataJSON(w, result, http.StatusOK)
}

func respondWithDataJSON(w http.ResponseWriter, data any, code int) error {
	result, err := json.Marshal(&struct {
		Data any `json:"data"`
	}{
		Data: data,
	})
	if err != nil {
		return respondWithJSON(w, []byte{'{', '}'}, http.StatusInternalServerError)
	}

	return respondWithJSON(w, result, code)
}

func respondWithErrJSON(w http.ResponseWriter, rerr error, code int) error {
	result, err := json.Marshal(&struct {
		Error string `json:"error"`
	}{
		Error: rerr.Error(),
	})
	if err != nil {
		return respondWithJSON(w, []byte{'{', '}'}, http.StatusInternalServerError)
	}

	return respondWithJSON(w, result, code)
}

func respondWithJSON(w http.ResponseWriter, data []byte, code int) error {
	w.Header().Add("Content-Type", "application/json")

	w.WriteHeader(code)
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}
