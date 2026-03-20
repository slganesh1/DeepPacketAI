package correlation

import "DeepPacketAI/internal/domain"

type mediaEndpoint struct {
	ip   string
	port int
}

func CorrelateSIPRTP(flows []domain.Flow) []domain.Call {
	var sipFlows []domain.Flow
	var rtpFlows []domain.Flow

	for _, f := range flows {
		switch f.Type {
		case domain.FlowSIP:
			sipFlows = append(sipFlows, f)
		case domain.FlowRTP:
			rtpFlows = append(rtpFlows, f)
		}
	}

	// Deduplicate SIP flows by Call-ID (FlowID). Multiple workers may produce
	// separate flows for the same Call-ID when packets traverse different IP pairs
	// (e.g., via proxy or after transfer). Keep the first occurrence.
	seen := make(map[string]bool)
	dedupSIP := sipFlows[:0]
	for _, sip := range sipFlows {
		if seen[sip.FlowID] {
			continue
		}
		seen[sip.FlowID] = true
		dedupSIP = append(dedupSIP, sip)
	}
	sipFlows = dedupSIP

	// Build allowed RTP endpoints from SDP
	allowed := make(map[mediaEndpoint]bool)
	for _, sip := range sipFlows {
		ip, _ := sip.Metrics["media_ip"].(string)
		portStr, _ := sip.Metrics["media_port"].(string)
		if ip == "" || portStr == "" {
			continue
		}
		port := atoi(portStr)
		allowed[mediaEndpoint{ip, port}] = true
	}

	var calls []domain.Call

	for _, sip := range sipFlows {
		mediaIP, _ := sip.Metrics["media_ip"].(string)
		mediaPortStr, _ := sip.Metrics["media_port"].(string)
		if mediaIP == "" || mediaPortStr == "" {
			continue
		}
		mediaPort := atoi(mediaPortStr)

		call := domain.Call{
			CallID:     sip.FlowID,
			StartTime:  sip.StartTime,
			EndTime:    sip.EndTime,
			SIPMetrics: sip.Metrics,
		}

		for _, rtp := range rtpFlows {
			if !isValidRTP(rtp, allowed) {
				continue
			}

			if (rtp.SrcIP == mediaIP || rtp.DstIP == mediaIP) &&
				(int(rtp.SrcPort) == mediaPort ||
					int(rtp.DstPort) == mediaPort) {

				call.RTPLegs = append(call.RTPLegs, rtp.Metrics)
			}
		}

		calls = append(calls, call)
	}

	return calls
}

func isValidRTP(rtp domain.Flow, allowed map[mediaEndpoint]bool) bool {
	_, ok1 := allowed[mediaEndpoint{rtp.SrcIP, int(rtp.SrcPort)}]
	_, ok2 := allowed[mediaEndpoint{rtp.DstIP, int(rtp.DstPort)}]
	return ok1 || ok2
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
