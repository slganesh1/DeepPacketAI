package ws

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"DeepPacketAI/internal/metrics"
	"github.com/gorilla/websocket"
)

// Hub manages all WebSocket clients and broadcasts messages.
type Hub struct {
	clients        map[*Client]bool
	broadcast      chan []byte
	register       chan *Client
	unregister     chan *Client
	mu             sync.RWMutex
	OnCommand      func(c *Client, cmd *ClientCommand)
	allowedOrigins map[string]bool // set via SetAllowedOrigins
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 8192),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// SetAllowedOrigins configures which HTTP origins may upgrade to WebSocket.
// If never called (or called with an empty slice), all origins are allowed
// (development fallback).
func (h *Hub) SetAllowedOrigins(origins []string) {
	m := make(map[string]bool, len(origins))
	for _, o := range origins {
		m[o] = true
	}
	h.mu.Lock()
	h.allowedOrigins = m
	h.mu.Unlock()
}

func (h *Hub) checkOrigin(r *http.Request) bool {
	h.mu.RLock()
	allowed := h.allowedOrigins
	h.mu.RUnlock()
	if len(allowed) == 0 {
		return true // development mode: no restriction
	}
	origin := r.Header.Get("Origin")
	return allowed[origin]
}

// Run starts the hub event loop. Call in a goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			count := len(h.clients)
			h.mu.Unlock()
			metrics.WSClients.Set(float64(count))
			log.Printf("ws client connected (%d total)", count)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			count := len(h.clients)
			h.mu.Unlock()
			metrics.WSClients.Set(float64(count))
			log.Printf("ws client disconnected (%d total)", count)

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

// Broadcast sends a message to all connected clients.
// Non-blocking: drops the message silently if the broadcast channel is full
// so that a slow or absent UI client never back-pressures the capture path.
func (h *Hub) Broadcast(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("ws broadcast marshal error: %v", err)
		return
	}
	select {
	case h.broadcast <- data:
	default:
		// channel full — drop rather than block the capture goroutine
	}
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// HandleWS is the HTTP handler for WebSocket upgrade.
// Auth is enforced at the router level via RequireAuth middleware before this
// handler is reached. Origin is validated here against SetAllowedOrigins.
func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: h.checkOrigin}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}

	client := NewClient(h, conn)
	h.register <- client

	go client.WritePump()
	go client.ReadPump()
}
