package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"DeepPacketAI/internal/storage"
)

// ── Auth session persistence ──────────────────────────────────────────────────

func (s *PostgresStore) CreateSession(token, username string, expiresAt time.Time) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO UPDATE SET username=EXCLUDED.username, expires_at=EXCLUDED.expires_at`,
		token, username, expiresAt,
	)
	return err
}

func (s *PostgresStore) GetSession(token string) (string, bool, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	var username string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT username, expires_at FROM sessions WHERE token = $1`, token,
	).Scan(&username, &expiresAt)
	if err != nil {
		return "", false, nil
	}
	if time.Now().After(expiresAt) {
		return "", false, nil
	}
	return username, true, nil
}

func (s *PostgresStore) DeleteSession(token string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	return err
}

func (s *PostgresStore) PurgeExpiredSessions() error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	return err
}

// PostgresStore implements storage.Store backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

const queryTimeout = 10 * time.Second
const writeTimeout = 30 * time.Second

func queryCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), queryTimeout)
}

func writeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), writeTimeout)
}

// New opens a pgxpool connection and runs migrations.
func New(dsn string) (*PostgresStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	s := &PostgresStore{pool: pool}
	if err := s.runMigrations(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return s, nil
}

// Close closes the connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

func init() {
	storage.RegisterPostgres(func(dsn string) (storage.Store, error) {
		return New(dsn)
	})
}
