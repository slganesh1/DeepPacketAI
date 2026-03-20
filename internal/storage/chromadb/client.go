package chromadb

import "DeepPacketAI/internal/domain/insight"

type Client interface {
    Store(ins insight.Insight, embedding []float32) error
    Query(text string, topK int) ([]insight.Insight, error)
}
