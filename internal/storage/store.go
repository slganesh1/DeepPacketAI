package storage

import (
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/web/api"
)

// Store is the unified storage interface implemented by SQLiteStore and PostgresStore.
type Store interface {
	// Job lifecycle
	// CreateJob inserts a new job row and returns the DB-assigned ID.
	CreateJob(pcap string) (int64, error)
	FailJob(jobID int64, reason string) error
	CompleteJob(jobID int64) error
	ClearJobData(jobID int64) error
	DeleteJob(jobID int64) error
	ResetStaleJobs()
	GetJob(jobID int64) (*api.JobItem, error)
	ListJobs(limit int, status string) ([]api.JobItem, error)

	// Maintenance
	PurgeAllPackets() error

	// Packets
	StorePackets(jobID int64, sessionID string, packets []*domain.Packet) error
	StorePacketsBatch(packets []PacketRecord) error
	QueryPackets(filters map[string]string, limit, offset int) ([]PacketRecord, error)
	GetPacketByID(id int64) (*PacketRecord, error)
	GetPacketCount(filters map[string]string) (int64, error)

	// Flows
	StoreFlows(jobID int64, flows []domain.Flow) error
	GetAllFlows() ([]domain.Flow, error)
	GetFlowsByJob(jobID int64) ([]domain.Flow, error)
	GetSIPFlowMetrics(callID string) (map[string]any, error)

	// Telecom sessions
	StoreTelecomSessions(jobID int64, sessions []domain.TelecomSession) error
	ListTelecomSessions(jobID int64) ([]domain.TelecomSession, error)
	GetTelecomSession(jobID int64, sessionID string) (*domain.TelecomSession, error)
	ListAllTelecomSessions() ([]domain.TelecomSession, error)

	// Calls & RTP
	StoreCalls(jobID int64, calls []domain.Call) error
	StoreRTPLegs(jobID int64, calls []domain.Call) error
	GetAllCalls() ([]domain.Call, error)
	GetCallsByJob(jobID int64) ([]domain.Call, error)
	GetCallByID(callID string) (*domain.Call, error)
	GetRTPLegsForCall(callID string) ([]map[string]any, error)

	// Entities
	ListCallEntities(jobID *int64, quality *string, rootCause *string, limit int, offset int) ([]api.EntityItem, int, error)
	GetEntityWithRTPLegs(callID string) (*api.EntityItem, []map[string]any, error)
	GetEntityByCallID(callID string) (*api.EntityItem, error)
	ListEntitiesForJob(jobID int64, limit int, quality string) ([]api.EntityItem, error)
	GetMetricsForCall(callID string) (*api.EntityMetrics, error)
	GetEventsForCall(callID string) ([]api.TimelineEvent, error)
	GetCallFlow(entityID string) (*CallFlowResult, error)

	// Protocol events / alerts
	StoreEvents(events []EventRecord) error
	QueryEvents(filters map[string]string, limit int) ([]EventRecord, error)

	// Live capture sessions
	StoreCaptureSession(rec CaptureSessionRecord) error
	QueryCaptureSessions() ([]CaptureSessionRecord, error)

	// Traffic stats
	StoreTrafficStats(records []TrafficStatsRecord) error
	QueryTrafficStats(sessionID string, limit int) ([]TrafficStatsRecord, error)

	// Stats queries (replaces raw DB().Query)
	GetProtocolCounts(jobID *int64) ([]map[string]any, error)
	GetTopTalkers(jobID *int64, limit int) ([]map[string]any, error)

	// GeoIP / IP reputation enrichment
	UpsertIPEnrichment(e IPEnrichment) error
	GetIPEnrichment(ip string) (*IPEnrichment, error)
	BulkGetIPEnrichments(ips []string) (map[string]IPEnrichment, error)
	GetGeoSummary(limit int) ([]GeoSummaryRow, error)
	GetFlaggedIPs(limit int) ([]IPEnrichment, error)

	// User-defined detection rules
	CreateUserRule(r UserDetectionRule) (int64, error)
	UpdateUserRule(r UserDetectionRule) error
	DeleteUserRule(id int64) error
	GetUserRule(id int64) (*UserDetectionRule, error)
	ListUserRules() ([]UserDetectionRule, error)

	// Alert targets (webhook/Slack/email notification rules)
	CreateAlertTarget(t AlertTarget) (int64, error)
	UpdateAlertTarget(t AlertTarget) error
	DeleteAlertTarget(id int64) error
	GetAlertTarget(id int64) (*AlertTarget, error)
	ListAlertTargets() ([]AlertTarget, error)

	// Chat
	CreateConversation(conv Conversation) error
	ListConversations() ([]Conversation, error)
	GetConversation(id string) (*Conversation, []ChatMessage, error)
	AddChatMessage(msg ChatMessage) error
	DeleteConversation(id string) error

	// Sessions (persisted across restarts)
	CreateSession(token, username string, expiresAt time.Time) error
	GetSession(token string) (username string, ok bool, err error)
	DeleteSession(token string) error
	PurgeExpiredSessions() error

	Close() error
}
