package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"DeepPacketAI/internal/storage"
)

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
