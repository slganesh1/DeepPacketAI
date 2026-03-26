package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"DeepPacketAI/internal/geoip"
	"DeepPacketAI/internal/storage"
)

// GeoHandler serves GeoIP lookup and summary endpoints.
type GeoHandler struct {
	store   storage.Store
	enricher *geoip.Enricher
}

func NewGeoHandler(db storage.Store, e *geoip.Enricher) *GeoHandler {
	return &GeoHandler{store: db, enricher: e}
}

// LookupIP GET /api/v1/geo/ip/{ip}
func (h *GeoHandler) LookupIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	result, err := h.enricher.LookupOne(r.Context(), ip)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Summary GET /api/v1/geo/summary?limit=20
func (h *GeoHandler) Summary(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	countries, err := h.store.GetGeoSummary(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	flagged, err := h.store.GetFlaggedIPs(50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if countries == nil {
		countries = []storage.GeoSummaryRow{}
	}
	if flagged == nil {
		flagged = []storage.IPEnrichment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"countries": countries,
		"flagged":   flagged,
	})
}

// EnrichIPs POST /api/v1/geo/enrich  body: {"ips": ["1.2.3.4", ...]}
func (h *GeoHandler) EnrichIPs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.IPs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ips array required"})
		return
	}
	go h.enricher.EnrichIPs(r.Context(), body.IPs)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "enrichment queued"})
}
