package handlers

import (
	"bytes"
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

// pcapMagicBytes lists the valid 4-byte file signatures for pcap and pcapng.
var pcapMagicBytes = [][]byte{
	{0xd4, 0xc3, 0xb2, 0xa1}, // pcap little-endian
	{0xa1, 0xb2, 0xc3, 0xd4}, // pcap big-endian
	{0x4d, 0x3c, 0xb2, 0xa1}, // pcap-ns little-endian (nanosecond timestamps)
	{0xa1, 0xb2, 0x3c, 0x4d}, // pcap-ns big-endian
	{0x0a, 0x0d, 0x0d, 0x0a}, // pcapng
}

func isPCAP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	for _, magic := range pcapMagicBytes {
		if bytes.Equal(data[:4], magic) {
			return true
		}
	}
	return false
}

type UploadHandler struct {
	store      storage.Store
	executor   *execution.Executor
	uploadsDir string
}

func NewUploadHandler(db storage.Store, uploadsDir string) *UploadHandler {
	if uploadsDir == "" {
		uploadsDir = "uploads"
	}
	return &UploadHandler{
		store:      db,
		executor:   execution.NewExecutor(db),
		uploadsDir: uploadsDir,
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

	// Validate PCAP magic bytes before touching the filesystem.
	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too small to be a valid PCAP"})
		return
	}
	if !isPCAP(magic) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file is not a valid PCAP or PCAPNG (bad magic bytes)"})
		return
	}
	// Seek back so the full file (including the 4 bytes we peeked) is written.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to reset file reader"})
		return
	}

	// Ensure uploads directory exists
	uploadsDir := h.uploadsDir
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

	jobID, err := h.store.CreateJob(destPath)
	if err != nil {
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
