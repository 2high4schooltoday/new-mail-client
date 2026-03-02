package pamreset

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestValidateRequestLimits(t *testing.T) {
	okReq := Request{
		RequestID:   "req-1",
		Username:    "webmaster",
		NewPassword: "SecretPass123!",
	}
	if err := validateRequest(okReq); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	tooLongUser := okReq
	tooLongUser.Username = string(bytes.Repeat([]byte("u"), MaxUsernameBytes+1))
	if err := validateRequest(tooLongUser); err == nil {
		t.Fatalf("expected username length validation error")
	}

	tooLongPassword := okReq
	tooLongPassword.NewPassword = string(bytes.Repeat([]byte("p"), MaxPasswordBytes+1))
	if err := validateRequest(tooLongPassword); err == nil {
		t.Fatalf("expected password length validation error")
	}
}

func TestFrameReadWriteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"ok":true}`)
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	out, err := readFrame(&buf, MaxFrameSize)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("unexpected payload: %q", string(out))
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte("x"), MaxFrameSize+1)
	if err := writeFrame(&buf, payload); err == nil {
		t.Fatalf("expected oversized payload write failure")
	}
}

func TestAuthorizePeerByUIDAndGID(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/pamreset-peercred-%d.sock", time.Now().UnixNano())
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer l.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		cfgOK := HelperConfig{
			AllowedUID: os.Getuid(),
			AllowedGID: os.Getgid(),
		}
		if err := authorizePeer(conn, cfgOK); err != nil {
			done <- err
			return
		}
		cfgBad := HelperConfig{
			AllowedUID: os.Getuid() + 10000,
			AllowedGID: os.Getgid(),
		}
		if err := authorizePeer(conn, cfgBad); err == nil {
			done <- err
			return
		}
		done <- nil
	}()

	client, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()
	if err := <-done; err != nil {
		t.Fatalf("peer authorization test failed: %v", err)
	}
}
