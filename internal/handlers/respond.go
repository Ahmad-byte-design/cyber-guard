package handlers

import (
	"encoding/json"
	"net/http"
)

// Response envelope.
//
// Every endpoint answers in one of two shapes, so a client parses outcomes
// uniformly:
//
//	{"success": true,  "message": "...", "data": ...}                (check-url)
//	{"success": true,  "message", "version", "updated", "data"}      (get-all)
//	{"success": false, "message": "...", "error": {"code": "...", "status": N}}

type response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type errorDetail struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

type errorResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Error   errorDetail `json:"error"`
}

// writeJSON serialises body with a JSON content type.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeOK answers with a success envelope.
func writeOK(w http.ResponseWriter, status int, message string, data any) {
	writeJSON(w, status, response{Success: true, Message: message, Data: data})
}

// writeError answers with the error envelope. The message is written for the
// API client: it never contains a submitted URL, the API key, provider prose
// or a database message.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, errorResponse{
		Success: false,
		Message: message,
		Error:   errorDetail{Code: code, Status: status},
	})
}
