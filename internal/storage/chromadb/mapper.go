package chromadb

import "DeepPacketAI/internal/domain/insight"

func InsightToDocument(ins insight.Insight) (string, map[string]string) {
    text := ins.Title + ". " + ins.Description

    metadata := map[string]string{
        "call_id":   ins.CallID,
        "type":      string(ins.Type),
        "severity":  string(ins.Severity),
    }

    return text, metadata
}
