package handlers

import (
	"net/http"
	"strconv"

	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/web/api"

	//"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type EntityHandler struct {
	DB storage.Store
}

func NewEntityHandler(db storage.Store) *EntityHandler {
	return &EntityHandler{DB: db}
}

func (h *EntityHandler) ListEntities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var (
		jobID     *int64
		quality  *string
		root     *string
		limit    = 50
		offset   = 0
	)

	if v := q.Get("job_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		jobID = &id
	}
	if v := q.Get("quality"); v != "" {
		quality = &v
	}
	if v := q.Get("root_cause"); v != "" {
		root = &v
	}
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}

	items, total, err := h.DB.ListCallEntities(
		jobID,
		quality,
		root,
		limit,
		offset,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.JSON(w, r, api.EntityListResponse{
		Total: total,
		Items: items,
	})
}
