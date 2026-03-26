// Package geoip enriches IP addresses with geographic location and reputation
// data. It uses the ip-api.com batch HTTP API (free, no key required) for geo
// data and the AbuseIPDB API (optional — needs ABUSEIPDB_API_KEY env var) for
// reputation scores.
//
// All results are cached in the application database with a 7-day TTL so that
// repeated analysis of the same traffic does not hit the external APIs.
package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"DeepPacketAI/internal/storage"
)

const (
	// ipAPIBatchURL is the ip-api.com batch endpoint (max 100 IPs, 45 req/min free tier).
	ipAPIBatchURL = "http://ip-api.com/batch"
	ipAPIFields   = "status,country,countryCode,city,lat,lon,isp,org,hosting,proxy,tor"

	// abuseIPDBURL is the AbuseIPDB check endpoint.
	abuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

	batchSize = 100
)

// Enricher performs IP geo and reputation lookups with DB-backed caching.
type Enricher struct {
	store      storage.Store
	client     *http.Client
	abuseKey   string
	mu         sync.Mutex // guards in-flight deduplication
	inflight   map[string]struct{}
}

// New creates an Enricher. It reads ABUSEIPDB_API_KEY from the environment.
func New(store storage.Store) *Enricher {
	return &Enricher{
		store:    store,
		client:   &http.Client{Timeout: 15 * time.Second},
		abuseKey: os.Getenv("ABUSEIPDB_API_KEY"),
		inflight: make(map[string]struct{}),
	}
}

// EnrichIPs enriches a set of IPs. Cached results (< 7 days old) are reused.
// New IPs are fetched in batches from ip-api.com, then optionally from AbuseIPDB.
// This function is designed to be called in a goroutine — it does not block callers.
func (e *Enricher) EnrichIPs(ctx context.Context, ips []string) {
	// Deduplicate, skip private/loopback
	seen := make(map[string]struct{})
	var toFetch []string
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		if isPrivate(ip) {
			continue
		}
		// Check DB cache
		cached, err := e.store.GetIPEnrichment(ip)
		if err == nil && cached != nil {
			continue // still fresh
		}
		toFetch = append(toFetch, ip)
	}

	if len(toFetch) == 0 {
		return
	}

	// Batch geo lookup
	for i := 0; i < len(toFetch); i += batchSize {
		end := i + batchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]
		results, err := e.fetchGeo(ctx, batch)
		if err != nil {
			log.Printf("geoip: batch lookup error: %v", err)
			continue
		}
		for _, r := range results {
			enrichment := storage.IPEnrichment{
				IP:          r.Query,
				CountryCode: r.CountryCode,
				Country:     r.Country,
				City:        r.City,
				ISP:         r.ISP,
				Org:         r.Org,
				Lat:         r.Lat,
				Lon:         r.Lon,
				IsHosting:   r.Hosting,
				IsTor:       r.Tor,
				IsProxy:     r.Proxy,
				LastChecked: time.Now(),
			}
			// Optionally enrich with AbuseIPDB
			if e.abuseKey != "" {
				score, abusive := e.fetchReputation(ctx, r.Query)
				enrichment.AbuseScore = score
				enrichment.IsAbusive = abusive
			}
			if err := e.store.UpsertIPEnrichment(enrichment); err != nil {
				log.Printf("geoip: store error for %s: %v", r.Query, err)
			}
		}
	}
}

// LookupOne returns the enrichment for a single IP, fetching if not cached.
func (e *Enricher) LookupOne(ctx context.Context, ip string) (*storage.IPEnrichment, error) {
	if isPrivate(ip) {
		return &storage.IPEnrichment{IP: ip, Country: "Private", CountryCode: "XX"}, nil
	}
	cached, err := e.store.GetIPEnrichment(ip)
	if err == nil && cached != nil {
		return cached, nil
	}
	results, err := e.fetchGeo(ctx, []string{ip})
	if err != nil || len(results) == 0 {
		return nil, fmt.Errorf("geo lookup failed for %s: %w", ip, err)
	}
	r := results[0]
	enrichment := storage.IPEnrichment{
		IP: r.Query, CountryCode: r.CountryCode, Country: r.Country,
		City: r.City, ISP: r.ISP, Org: r.Org, Lat: r.Lat, Lon: r.Lon,
		IsHosting: r.Hosting, IsTor: r.Tor, IsProxy: r.Proxy, LastChecked: time.Now(),
	}
	if e.abuseKey != "" {
		enrichment.AbuseScore, enrichment.IsAbusive = e.fetchReputation(ctx, ip)
	}
	_ = e.store.UpsertIPEnrichment(enrichment)
	return &enrichment, nil
}

// ── ip-api.com ────────────────────────────────────────────────────────────────

type ipAPIEntry struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	Hosting     bool    `json:"hosting"`
	Proxy       bool    `json:"proxy"`
	Tor         bool    `json:"tor"`
	Query       string  `json:"query"`
}

func (e *Enricher) fetchGeo(ctx context.Context, ips []string) ([]ipAPIEntry, error) {
	body, _ := json.Marshal(ips)
	url := ipAPIBatchURL + "?fields=" + ipAPIFields

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []ipAPIEntry
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	// Filter out failed lookups
	var ok []ipAPIEntry
	for _, r := range results {
		if r.Status == "success" {
			ok = append(ok, r)
		}
	}
	return ok, nil
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int  `json:"abuseConfidenceScore"`
		TotalReports         int  `json:"totalReports"`
		IsPublic             bool `json:"isPublic"`
	} `json:"data"`
}

// fetchReputation returns (score 0-100, isAbusive).
func (e *Enricher) fetchReputation(ctx context.Context, ip string) (int, bool) {
	url := fmt.Sprintf("%s?ipAddress=%s&maxAgeInDays=90", abuseIPDBURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Key", e.abuseKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	var r abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, false
	}
	return r.Data.AbuseConfidenceScore, r.Data.AbuseConfidenceScore > 25
}

// ── helpers ───────────────────────────────────────────────────────────────────

var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
		"100.64.0.0/10", // Carrier-grade NAT
	}
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		if n != nil {
			privateRanges = append(privateRanges, n)
		}
	}
}

func isPrivate(ipStr string) bool {
	// Strip port if present
	if idx := strings.LastIndex(ipStr, ":"); idx > 0 {
		if strings.Count(ipStr, ":") == 1 { // IPv4:port
			ipStr = ipStr[:idx]
		}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unparseable → treat as private to skip
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
