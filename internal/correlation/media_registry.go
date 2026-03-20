package correlation

type MediaRegistry struct {
	callMedia map[string]MediaInfo
}

type MediaInfo struct {
	IP        string
	Port      string
  RTPIP    string
	RTPPort  string
	Direction string
}

func NewMediaRegistry() *MediaRegistry {
	return &MediaRegistry{
		callMedia: make(map[string]MediaInfo),
	}
}

func (m *MediaRegistry) Register(callID string, info MediaInfo) {
	m.callMedia[callID] = info
}

func (m *MediaRegistry) Match(ip, port string) (string, bool) {
	for callID, media := range m.callMedia {
		if media.IP == ip && media.Port == port {
			return callID, true
		}
    if media.RTPIP == ip && media.RTPPort == port {
			return callID, true
		}
	}
	return "", false
}

func (m *MediaRegistry) LearnRTP(callID, ip, port string) {
	media, ok := m.callMedia[callID]
	if !ok {
		return
	}

	// Learn only once
	if media.RTPIP == "" {
		media.RTPIP = ip
		media.RTPPort = port
		m.callMedia[callID] = media
	}
}

