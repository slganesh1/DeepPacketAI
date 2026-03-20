package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"DeepPacketAI/internal/execution"
	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

type UploadHandler struct {
	store    storage.Store
	executor *execution.Executor
}

func NewUploadHandler(db storage.Store) *UploadHandler {
	return &UploadHandler{
		store:    db,
		executor: execution.NewExecutor(db),
	}
}

func (h *UploadHandler) UploadPCAP(w http.ResponseWriter, r *http.Request) {
	// Limit upload to 500MB
	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid form"})
		return
	}

	file, header, err := r.FormFile("pcap")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'pcap' file field"})
		return
	}
	defer file.Close()

	// Ensure uploads directory exists
	uploadsDir := "uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create uploads directory"})
		return
	}

	// Save file with timestamp prefix to avoid collisions
	filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(header.Filename))
	destPath := filepath.Join(uploadsDir, filename)

	dst, err := os.Create(destPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to write file"})
		return
	}

	// Create job first, then start async analysis with the same ID
	// Use milliseconds (not nanoseconds) so the ID fits in JavaScript's safe integer range
	jobID := time.Now().UnixMilli()
	if err := h.store.CreateJob(jobID, destPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create job"})
		return
	}
	go func() {
		_ = h.executor.RunPCAPForJob(jobID, destPath)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"job_id":   jobID,
		"filename": header.Filename,
		"status":   "processing",
		"message":  "PCAP uploaded and analysis started",
	})
}

// ReprocessJob re-analyzes an existing job's PCAP file with current decoders.
func (h *UploadHandler) ReprocessJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	jobID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job ID"})
		return
	}

	job, err := h.store.GetJob(jobID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}

	// Verify PCAP file still exists
	if _, err := os.Stat(job.PCAPPath); os.IsNotExist(err) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "PCAP file no longer exists"})
		return
	}

	// Clear existing analysis data and reset status
	if err := h.store.ClearJobData(jobID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear job data"})
		return
	}

	// Re-run analysis asynchronously
	go func() {
		if err := h.executor.RunPCAPForJob(jobID, job.PCAPPath); err != nil {
			log.Printf("reprocess job %d failed: %v", jobID, err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"job_id":  jobID,
		"status":  "processing",
		"message": "Job re-analysis started with updated decoders",
	})
}
