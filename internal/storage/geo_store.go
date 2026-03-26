package storage

import "time"

// IPEnrichment holds cached geo and reputation data for a single IP address.
type IPEnrichment struct {
	IP          string    `json:"ip"`
	CountryCode string    `json:"country_code"`
	Country     string    `json:"country"`
	City        string    `json:"city"`
	ISP         string    `json:"isp"`
	Org         string    `json:"org"`
	Lat         float64   `json:"lat"`
	Lon         float64   `json:"lon"`
	IsHosting   bool      `json:"is_hosting"`
	IsTor       bool      `json:"is_tor"`
	IsProxy     bool      `json:"is_proxy"`
	AbuseScore  int       `json:"abuse_score"`
	IsAbusive   bool      `json:"is_abusive"`
	LastChecked time.Time `json:"last_checked"`
}

// UpsertIPEnrichment inserts or replaces an IP enrichment record.
func (s *SQLiteStore) UpsertIPEnrichment(e IPEnrichment) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ip_enrichments
			(ip, country_code, country, city, isp, org, lat, lon,
			 is_hosting, is_tor, is_proxy, abuse_score, is_abusive, last_checked)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET
			country_code=excluded.country_code,
			country=excluded.country,
			city=excluded.city,
			isp=excluded.isp,
			org=excluded.org,
			lat=excluded.lat,
			lon=excluded.lon,
			is_hosting=excluded.is_hosting,
			is_tor=excluded.is_tor,
			is_proxy=excluded.is_proxy,
			abuse_score=excluded.abuse_score,
			is_abusive=excluded.is_abusive,
			last_checked=excluded.last_checked`,
		e.IP, e.CountryCode, e.Country, e.City, e.ISP, e.Org, e.Lat, e.Lon,
		boolInt(e.IsHosting), boolInt(e.IsTor), boolInt(e.IsProxy),
		e.AbuseScore, boolInt(e.IsAbusive), e.LastChecked.UTC().Format("2006-01-02T15:04:05Z"),
	)
	return err
}

// GetIPEnrichment returns a cached enrichment, or nil if not found / expired (>7 days).
func (s *SQLiteStore) GetIPEnrichment(ip string) (*IPEnrichment, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
		SELECT ip, country_code, country, city, isp, org, lat, lon,
		       is_hosting, is_tor, is_proxy, abuse_score, is_abusive, last_checked
		FROM ip_enrichments
		WHERE ip=? AND last_checked > datetime('now','-7 days')`, ip)

	return scanIPEnrichment(row)
}

// BulkGetIPEnrichments returns cached entries for a list of IPs (no TTL filter).
func (s *SQLiteStore) BulkGetIPEnrichments(ips []string) (map[string]IPEnrichment, error) {
	if len(ips) == 0 {
		return map[string]IPEnrichment{}, nil
	}
	ctx, cancel := queryCtx()
	defer cancel()

	// Build IN clause
	placeholders := make([]byte, 0, len(ips)*2)
	args := make([]any, len(ips))
	for i, ip := range ips {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args[i] = ip
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT ip, country_code, country, city, isp, org, lat, lon, is_hosting, is_tor, is_proxy, abuse_score, is_abusive, last_checked FROM ip_enrichments WHERE ip IN ("+string(placeholders)+")",
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]IPEnrichment, len(ips))
	for rows.Next() {
		e, err := scanIPEnrichment(rows)
		if err != nil {
			continue
		}
		result[e.IP] = *e
	}
	return result, nil
}

// GeoSummaryRow represents one row in the country distribution summary.
type GeoSummaryRow struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Count       int    `json:"count"`
}

// GetGeoSummary returns the top countries by enriched IP count.
func (s *SQLiteStore) GetGeoSummary(limit int) ([]GeoSummaryRow, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT country_code, country, COUNT(*) as cnt
		FROM ip_enrichments
		WHERE country_code != ''
		GROUP BY country_code, country
		ORDER BY cnt DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []GeoSummaryRow
	for rows.Next() {
		var r GeoSummaryRow
		if err := rows.Scan(&r.CountryCode, &r.Country, &r.Count); err != nil {
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

// GetFlaggedIPs returns IPs marked as abusive, tor, or hosting.
func (s *SQLiteStore) GetFlaggedIPs(limit int) ([]IPEnrichment, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, country_code, country, city, isp, org, lat, lon,
		       is_hosting, is_tor, is_proxy, abuse_score, is_abusive, last_checked
		FROM ip_enrichments
		WHERE is_abusive=1 OR is_tor=1 OR abuse_score > 25
		ORDER BY abuse_score DESC, is_tor DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []IPEnrichment
	for rows.Next() {
		e, err := scanIPEnrichment(rows)
		if err != nil {
			continue
		}
		result = append(result, *e)
	}
	return result, nil
}

func scanIPEnrichment(s scanner) (*IPEnrichment, error) {
	var e IPEnrichment
	var isHosting, isTor, isProxy, isAbusive int
	var lastCheckedStr string
	if err := s.Scan(
		&e.IP, &e.CountryCode, &e.Country, &e.City, &e.ISP, &e.Org,
		&e.Lat, &e.Lon, &isHosting, &isTor, &isProxy,
		&e.AbuseScore, &isAbusive, &lastCheckedStr,
	); err != nil {
		return nil, err
	}
	e.IsHosting = isHosting != 0
	e.IsTor = isTor != 0
	e.IsProxy = isProxy != 0
	e.IsAbusive = isAbusive != 0
	e.LastChecked, _ = time.Parse("2006-01-02T15:04:05Z", lastCheckedStr)
	return &e, nil
}
