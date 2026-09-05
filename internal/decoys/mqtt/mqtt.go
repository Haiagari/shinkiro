package mqtt

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "mqtt" }
func (d *Decoy) DefaultPort() int { return 1883 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	reader := bufio.NewReader(conn)

	for {
		headerByte, err := reader.ReadByte()
		if err != nil {
			return nil
		}

		packetType := (headerByte >> 4) & 0x0F

		// Read Remaining Length (MQTT variable length encoding, simplified 1-2 bytes)
		remLen, err := decodeRemainingLength(reader)
		if err != nil {
			return nil
		}

		payload := make([]byte, remLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil
		}

		hash := sha256.Sum256(payload)
		payloadHash := hex.EncodeToString(hash[:])

		switch packetType {
		case 1: // CONNECT
			clientID, username, password := parseConnectPayload(payload)

			event := intel.Event{
				ID:            fmt.Sprintf("mqtt-conn-%d", time.Now().UnixNano()),
				Timestamp:     time.Now().UTC(),
				DecoyName:     "mqtt",
				RemoteAddr:    remoteAddr,
				RemoteIP:      remoteIP,
				LocalPort:     1883,
				Severity:      intel.SeverityHigh,
				ThreatScore:   85,
				Action:        "MQTT_IOT_BOTNET_CONNECT",
				Username:      username,
				Password:      password,
				PayloadHashes: []string{payloadHash},
				Metadata: map[string]string{
					"client_id": clientID,
					
				},
			}

			select {
			case events <- event:
			default:
			}

			// Respond with CONNACK (Connection Accepted: 0x20, 0x02, 0x00, 0x00)
			connack := []byte{0x20, 0x02, 0x00, 0x00}
			_, _ = conn.Write(connack)

		case 3: // PUBLISH
			topic, msg := parsePublishPayload(payload)

			event := intel.Event{
				ID:            fmt.Sprintf("mqtt-pub-%d", time.Now().UnixNano()),
				Timestamp:     time.Now().UTC(),
				DecoyName:     "mqtt",
				RemoteAddr:    remoteAddr,
				RemoteIP:      remoteIP,
				LocalPort:     1883,
				Severity:      intel.SeverityCritical,
				ThreatScore:   95,
				Action:        "MQTT_IOT_EXPLOIT_PUBLISH",
				Command:       topic,
				PayloadHashes: []string{payloadHash},
				Metadata: map[string]string{
					"topic": topic,
					"message": msg,
				},
			}

			select {
			case events <- event:
			default:
			}

			// If QoS > 0, we can respond PUBACK (0x40, 0x02, packet_id)
			if (headerByte & 0x06) > 0 && len(payload) >= 2 {
				puback := []byte{0x40, 0x02, 0x00, 0x01}
				_, _ = conn.Write(puback)
			}

		case 8: // SUBSCRIBE
			event := intel.Event{
				ID:            fmt.Sprintf("mqtt-sub-%d", time.Now().UnixNano()),
				Timestamp:     time.Now().UTC(),
				DecoyName:     "mqtt",
				RemoteAddr:    remoteAddr,
				RemoteIP:      remoteIP,
				LocalPort:     1883,
				Severity:      intel.SeverityMedium,
				ThreatScore:   70,
				Action:        "MQTT_RECON_SUBSCRIBE",
				PayloadHashes: []string{payloadHash},
			}

			select {
			case events <- event:
			default:
			}

			// Respond SUBACK (0x90, 0x03, packet_id_msb, packet_id_lsb, return_code_success)
			suback := []byte{0x90, 0x03, 0x00, 0x01, 0x00}
			_, _ = conn.Write(suback)

		case 12: // PINGREQ
			_, _ = conn.Write([]byte{0xd0, 0x00}) // PINGRESP

		case 14: // DISCONNECT
			return nil

		default:
			// Unhandled packet
		}
	}
}

func decodeRemainingLength(r *bufio.Reader) (int, error) {
	multiplier := 1
	value := 0
	for {
		encodedByte, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(encodedByte&127) * multiplier
		if (encodedByte & 128) == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, fmt.Errorf("malformed remaining length")
		}
	}
	return value, nil
}

func parseConnectPayload(data []byte) (clientID, username, password string) {
	if len(data) < 10 {
		return "unknown", "", ""
	}
	// Protocol Name len (2 bytes), Protocol Name ("MQTT"), Level (1 byte), Flags (1 byte), KeepAlive (2 bytes)
	flags := data[7]
	offset := 10

	readString := func(d []byte, off *int) string {
		if *off+2 > len(d) {
			return ""
		}
		l := int(d[*off])<<8 | int(d[*off+1])
		*off += 2
		if *off+l > len(d) {
			return ""
		}
		s := string(d[*off : *off+l])
		*off += l
		return s
	}

	clientID = readString(data, &offset)
	if (flags & 0x80) != 0 { // Username Flag
		username = readString(data, &offset)
	}
	if (flags & 0x40) != 0 { // Password Flag
		password = readString(data, &offset)
	}

	return clientID, username, password
}

func parsePublishPayload(data []byte) (topic, message string) {
	if len(data) < 2 {
		return "", ""
	}
	topicLen := int(data[0])<<8 | int(data[1])
	if 2+topicLen > len(data) {
		return "", ""
	}
	topic = string(data[2 : 2+topicLen])
	msgBytes := data[2+topicLen:]
	message = string(msgBytes)
	return topic, message
}
