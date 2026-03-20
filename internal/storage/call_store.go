package storage

import (
	"sync"

	"DeepPacketAI/internal/domain"
)

// CallStore defines how correlated calls are stored.
// This abstraction allows swapping memory / sqlite / future backends.
type CallStore interface {
	StoreCalls(jobID int64, calls []domain.Call) error
	GetAllCalls() []domain.Call
	GetCallsByJob(jobID int64) []domain.Call
	Clear()
}

// MemoryCallStore is an in-memory implementation of CallStore.
// Useful for debugging, testing, and early GUI work.
type MemoryCallStore struct {
	mu    sync.Mutex
	calls []domain.Call
}

// NewMemoryCallStore creates a new in-memory call store.
func NewMemoryCallStore() *MemoryCallStore {
	return &MemoryCallStore{
		calls: make([]domain.Call, 0),
	}
}

// StoreCalls stores correlated calls for a job.
func (m *MemoryCallStore) StoreCalls(jobID int64, calls []domain.Call) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, calls...)
	return nil
}

// GetAllCalls returns all stored calls.
func (m *MemoryCallStore) GetAllCalls() []domain.Call {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]domain.Call, len(m.calls))
	copy(out, m.calls)
	return out
}

// GetCallsByJob returns calls for a given job.
// (Currently all calls belong to one job; kept for future expansion.)
func (m *MemoryCallStore) GetCallsByJob(jobID int64) []domain.Call {
	return m.GetAllCalls()
}

// Clear removes all stored calls.
func (m *MemoryCallStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = nil
}
