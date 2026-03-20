package storage

import "fmt"

// Config holds storage backend configuration.
type Config struct {
	Backend string // "sqlite" (default) or "postgres"
	DSN     string // file path for sqlite, postgres connection URL for postgres
}

// New creates a Store from config. Defaults to SQLite if Backend is empty.
func New(cfg Config) (Store, error) {
	switch cfg.Backend {
	case "postgres":
		// import cycle: postgres package imports storage, so we use a registered factory
		if pgFactory == nil {
			return nil, fmt.Errorf("postgres backend not registered; import _ \"DeepPacketAI/internal/storage/postgres\"")
		}
		return pgFactory(cfg.DSN)
	default:
		dsn := cfg.DSN
		if dsn == "" {
			dsn = "deeppacketai.db"
		}
		return NewSQLite(dsn)
	}
}

// pgFactory is set by the postgres package via RegisterPostgres to avoid import cycles.
var pgFactory func(dsn string) (Store, error)

// RegisterPostgres is called by the postgres package init() to register its constructor.
func RegisterPostgres(fn func(dsn string) (Store, error)) {
	pgFactory = fn
}
