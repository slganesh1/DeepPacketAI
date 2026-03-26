package postgres

import (
	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) UpsertIPEnrichment(e storage.IPEnrichment) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ip_enrichments
			(ip,country_code,country,city,isp,org,lat,lon,is_hosting,is_tor,is_proxy,abuse_score,is_abusive,last_checked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT(ip) DO UPDATE SET
			country_code=EXCLUDED.country_code, country=EXCLUDED.country, city=EXCLUDED.city,
			isp=EXCLUDED.isp, org=EXCLUDED.org, lat=EXCLUDED.lat, lon=EXCLUDED.lon,
			is_hosting=EXCLUDED.is_hosting, is_tor=EXCLUDED.is_tor, is_proxy=EXCLUDED.is_proxy,
			abuse_score=EXCLUDED.abuse_score, is_abusive=EXCLUDED.is_abusive, last_checked=EXCLUDED.last_checked`,
		e.IP, e.CountryCode, e.Country, e.City, e.ISP, e.Org, e.Lat, e.Lon,
		e.IsHosting, e.IsTor, e.IsProxy, e.AbuseScore, e.IsAbusive, e.LastChecked,
	)
	return err
}

func (s *PostgresStore) GetIPEnrichment(ip string) (*storage.IPEnrichment, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	var e storage.IPEnrichment
	err := s.pool.QueryRow(ctx, `
		SELECT ip,country_code,country,city,isp,org,lat,lon,is_hosting,is_tor,is_proxy,abuse_score,is_abusive,last_checked
		FROM ip_enrichments WHERE ip=$1 AND last_checked > NOW()-INTERVAL '7 days'`, ip).
		Scan(&e.IP, &e.CountryCode, &e.Country, &e.City, &e.ISP, &e.Org, &e.Lat, &e.Lon,
			&e.IsHosting, &e.IsTor, &e.IsProxy, &e.AbuseScore, &e.IsAbusive, &e.LastChecked)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *PostgresStore) BulkGetIPEnrichments(ips []string) (map[string]storage.IPEnrichment, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	result := make(map[string]storage.IPEnrichment)
	if len(ips) == 0 {
		return result, nil
	}
	args := make([]any, len(ips))
	placeholders := ""
	for i, ip := range ips {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "$" + string(rune('1'+i))
		args[i] = ip
	}
	rows, err := s.pool.Query(ctx,
		"SELECT ip,country_code,country,city,isp,org,lat,lon,is_hosting,is_tor,is_proxy,abuse_score,is_abusive,last_checked FROM ip_enrichments WHERE ip IN ("+placeholders+")",
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e storage.IPEnrichment
		if err := rows.Scan(&e.IP, &e.CountryCode, &e.Country, &e.City, &e.ISP, &e.Org, &e.Lat, &e.Lon,
			&e.IsHosting, &e.IsTor, &e.IsProxy, &e.AbuseScore, &e.IsAbusive, &e.LastChecked); err != nil {
			continue
		}
		result[e.IP] = e
	}
	return result, nil
}

func (s *PostgresStore) GetGeoSummary(limit int) ([]storage.GeoSummaryRow, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.pool.Query(ctx, `
		SELECT country_code, country, COUNT(*) FROM ip_enrichments
		WHERE country_code!='' GROUP BY country_code, country ORDER BY COUNT(*) DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []storage.GeoSummaryRow
	for rows.Next() {
		var r storage.GeoSummaryRow
		if err := rows.Scan(&r.CountryCode, &r.Country, &r.Count); err != nil {
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

func (s *PostgresStore) GetFlaggedIPs(limit int) ([]storage.IPEnrichment, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.pool.Query(ctx, `
		SELECT ip,country_code,country,city,isp,org,lat,lon,is_hosting,is_tor,is_proxy,abuse_score,is_abusive,last_checked
		FROM ip_enrichments WHERE is_abusive OR is_tor OR abuse_score>25
		ORDER BY abuse_score DESC, is_tor DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []storage.IPEnrichment
	for rows.Next() {
		var e storage.IPEnrichment
		if err := rows.Scan(&e.IP, &e.CountryCode, &e.Country, &e.City, &e.ISP, &e.Org, &e.Lat, &e.Lon,
			&e.IsHosting, &e.IsTor, &e.IsProxy, &e.AbuseScore, &e.IsAbusive, &e.LastChecked); err != nil {
			continue
		}
		result = append(result, e)
	}
	return result, nil
}
