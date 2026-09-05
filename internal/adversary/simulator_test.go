package adversary

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSimulator_RunScenario_MockServer(t *testing.T) {
	// Setup a simple TCP echo listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("BusyBox v1.31.1\r\n" + string(buf[:n])))
	}()

	sim := NewSimulator("127.0.0.1", 2*time.Second)
	scenario := AttackScenario{
		Name:        "Test Telnet",
		Protocol:    "tcp",
		Port:        port,
		Payload:     []byte("admin\n"),
		ExpectMatch: "BusyBox",
	}

	res, err := sim.RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatalf("run scenario failed: %v", err)
	}

	if len(res) == 0 {
		t.Fatal("expected non-empty response")
	}
}
