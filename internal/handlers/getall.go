package handlers

import (
	"net/http"
	"strconv"

	"cyberguard/internal/services"
)

// GET /api/v1/get-all — read stored submissions from MongoDB, newest first.
//
// This endpoint never contacts the provider: it serves exactly what has been
// persisted, and a record's verdict is null whenever the provider did not
// report one.

func (s *Server) handleGetAll(w http.ResponseWriter, r *http.Request) {
	if !checkMethod(w, r, http.MethodGet) {
		return
	}

	page, serr := paginationParam(r, "page", 1)
	if serr != nil {
		writeError(w, r, serr.Status, serr.Code, serr.Message)
		return
	}
	limit, serr := paginationParam(r, "limit", services.DefaultLimit)
	if serr != nil {
		writeError(w, r, serr.Status, serr.Code, serr.Message)
		return
	}
	if limit > services.MaxLimit {
		writeError(w, r, http.StatusBadRequest, services.CodeInvalidRequest,
			"limit must be at most "+strconv.Itoa(services.MaxLimit))
		return
	}

	items, pagination, serr := s.svc.List(r.Context(), page, limit)
	if serr != nil {
		s.logServiceError(r.Context(), "get-all", serr)
		writeError(w, r, serr.Status, serr.Code, serr.Message)
		return
	}

	writeOKPaged(w, http.StatusOK, items, pagination)
}

// paginationParam parses one pagination query parameter.
//
// An absent value means the default; a present-but-invalid value is a 400,
// because silently "fixing" an out-of-range page would misrepresent the
// collection's size to the caller.
func paginationParam(r *http.Request, name string, def int) (int, *services.Error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: name + " must be an integer",
		}
	}
	if n < 1 {
		return 0, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: name + " must be at least 1",
		}
	}
	if name == "page" && n > services.MaxPage {
		return 0, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: "page must be at most " + strconv.Itoa(services.MaxPage),
		}
	}
	return n, nil
}
