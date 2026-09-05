package modbus

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// Decoy emulates an ICS/SCADA Modbus/TCP Programmable Logic Controller (PLC)
type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "modbus" }
func (d *Decoy) DefaultPort() int { return 502 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	for {
		// Read Modbus TCP MBAP Header (7 bytes):
		// Transaction ID (2), Protocol ID (2, always 0), Length (2), Unit ID (1)
		mbap := make([]byte, 7)
		if _, err := io.ReadFull(conn, mbap); err != nil {
			return nil
		}

		protocolID := binary.BigEndian.Uint16(mbap[2:4])
		pduLen := binary.BigEndian.Uint16(mbap[4:6])
		unitID := mbap[6]

		if protocolID != 0 || pduLen < 1 || pduLen > 256 {
			return nil
		}

		pdu := make([]byte, pduLen-1)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			return nil
		}

		functionCode := pdu[0]
		actionName := resolveModbusFunction(functionCode)

		severity := intel.SeverityHigh
		threatScore := 75

		// Function codes like Write Single Coil (0x05) or Write Multiple Registers (0x10) represent active OT attacks
		if functionCode == 0x05 || functionCode == 0x06 || functionCode == 0x0F || functionCode == 0x10 {
			severity = intel.SeverityCritical
			threatScore = 95
		}

		event := intel.Event{
			ID:          fmt.Sprintf("modbus-%d", time.Now().UnixNano()),
			Timestamp:   time.Now().UTC(),
			DecoyName:   "modbus",
			RemoteAddr:  remoteAddr,
			RemoteIP:    remoteIP,
			LocalPort:   502,
			Severity:    severity,
			ThreatScore: threatScore,
			Action:      fmt.Sprintf("MODBUS_FC%02X_%s", functionCode, actionName),
			Metadata: map[string]string{
				"unit_id":       fmt.Sprintf("%d", unitID),
				"function_code": fmt.Sprintf("0x%02X", functionCode),
				"ics_protocol":  "Modbus/TCP",
			},
			Mitre: &intel.MitreAttack{
				TacticID:      "TA0108",
				TacticName:    "Inhibit Response Function",
				TechniqueID:   "T0855",
				TechniqueName: "Unauthorized Command Message",
				Reference:     "https://attack.mitre.org/techniques/T0855/",
			},
		}

		select {
		case events <- event:
		default:
		}

		// Synthetic Modbus PLC Response
		resp := buildModbusResponse(mbap, functionCode, pdu[1:])
		if len(resp) > 0 {
			_, _ = conn.Write(resp)
		}
	}
}

func resolveModbusFunction(fc byte) string {
	switch fc {
	case 0x01:
		return "READ_COILS"
	case 0x02:
		return "READ_DISCRETE_INPUTS"
	case 0x03:
		return "READ_HOLDING_REGISTERS"
	case 0x04:
		return "READ_INPUT_REGISTERS"
	case 0x05:
		return "WRITE_SINGLE_COIL"
	case 0x06:
		return "WRITE_SINGLE_REGISTER"
	case 0x08:
		return "DIAGNOSTICS"
	case 0x0F:
		return "WRITE_MULTIPLE_COILS"
	case 0x10:
		return "WRITE_MULTIPLE_REGISTERS"
	default:
		return "PROBE_UNKNOWN_FC"
	}
}

func buildModbusResponse(mbap []byte, fc byte, pduPayload []byte) []byte {
	// Standard response: Echo MBAP with response payload
	switch fc {
	case 0x03, 0x04: // Read Registers
		// Return 2 registers with synthetic telemetry: 0x04, reg1=220V (0x00DC), reg2=50Hz (0x0032)
		body := []byte{fc, 4, 0x00, 0xDC, 0x00, 0x32}
		resp := make([]byte, 6+len(body))
		copy(resp[0:4], mbap[0:4])
		binary.BigEndian.PutUint16(resp[4:6], uint16(len(body)+1)) // Len includes UnitID
		resp[6] = mbap[6]                                          // Unit ID
		copy(resp[7:], body)
		return resp
	case 0x01, 0x02: // Read Coils
		body := []byte{fc, 1, 0x01} // 1 byte, coil 0 ON
		resp := make([]byte, 6+len(body))
		copy(resp[0:4], mbap[0:4])
		binary.BigEndian.PutUint16(resp[4:6], uint16(len(body)+1))
		resp[6] = mbap[6]
		copy(resp[7:], body)
		return resp
	default:
		// Echo write confirmation
		if len(pduPayload) >= 4 {
			body := append([]byte{fc}, pduPayload[0:4]...)
			resp := make([]byte, 6+len(body))
			copy(resp[0:4], mbap[0:4])
			binary.BigEndian.PutUint16(resp[4:6], uint16(len(body)+1))
			resp[6] = mbap[6]
			copy(resp[7:], body)
			return resp
		}
		return nil
	}
}
