package pamreset

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	MaxFrameSize      = 8192
	MaxUsernameBytes  = 128
	MaxPasswordBytes  = 4096
	ProtocolCodeOK    = "ok"
	ProtocolCodeError = "helper_failed"
)

var (
	ErrHelperUnavailable = errors.New("pam reset helper unavailable")
	ErrHelperRejected    = errors.New("pam reset helper rejected request")
)

type Request struct {
	RequestID   string `json:"request_id"`
	Username    string `json:"username"`
	NewPassword string `json:"new_password"`
}

type Response struct {
	RequestID string `json:"request_id"`
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
}

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func (c Client) ResetPassword(ctx context.Context, req Request) (Response, error) {
	if strings.TrimSpace(c.SocketPath) == "" {
		return Response{}, ErrHelperUnavailable
	}
	if err := validateRequest(req); err != nil {
		return Response{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if err := writeFrame(conn, payload); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	frame, err := readFrame(conn, MaxFrameSize)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	var out Response
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return Response{}, fmt.Errorf("%w: bad helper response", ErrHelperUnavailable)
	}
	if strings.TrimSpace(out.RequestID) != strings.TrimSpace(req.RequestID) {
		return Response{}, fmt.Errorf("%w: request id mismatch", ErrHelperUnavailable)
	}
	if !out.OK {
		return out, fmt.Errorf("%w: %s", ErrHelperRejected, strings.TrimSpace(out.Code))
	}
	return out, nil
}

type HelperConfig struct {
	SocketPath      string
	SocketGroupID   int
	AllowedUID      int
	AllowedGID      int
	IOTimeout       time.Duration
	CommandTimeout  time.Duration
	SocketFilePerms os.FileMode
}

func (c HelperConfig) normalized() HelperConfig {
	if c.IOTimeout <= 0 {
		c.IOTimeout = 5 * time.Second
	}
	if c.CommandTimeout <= 0 {
		c.CommandTimeout = 5 * time.Second
	}
	if c.SocketFilePerms == 0 {
		c.SocketFilePerms = 0660
	}
	return c
}

func RunServer(ctx context.Context, cfg HelperConfig) error {
	cfg = cfg.normalized()
	if strings.TrimSpace(cfg.SocketPath) == "" {
		return fmt.Errorf("socket path is required")
	}
	if err := os.MkdirAll(filepathDir(cfg.SocketPath), 0755); err != nil {
		return err
	}
	_ = os.Remove(cfg.SocketPath)

	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.SocketPath)
	}()
	if err := os.Chmod(cfg.SocketPath, cfg.SocketFilePerms); err != nil {
		return err
	}
	groupID := cfg.SocketGroupID
	if groupID < 0 {
		groupID = cfg.AllowedGID
	}
	if err := os.Chown(cfg.SocketPath, 0, groupID); err != nil {
		return err
	}

	closer := sync.Once{}
	go func() {
		<-ctx.Done()
		closer.Do(func() { _ = listener.Close() })
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go handleConn(conn, cfg)
	}
}

func handleConn(conn net.Conn, cfg HelperConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.IOTimeout))

	if err := authorizePeer(conn, cfg); err != nil {
		_ = writeResponse(conn, Response{RequestID: "", OK: false, Code: "unauthorized_peer"})
		return
	}

	frame, err := readFrame(conn, MaxFrameSize)
	if err != nil {
		_ = writeResponse(conn, Response{RequestID: "", OK: false, Code: "invalid_frame"})
		return
	}
	defer zero(frame)

	var req Request
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		_ = writeResponse(conn, Response{RequestID: "", OK: false, Code: "invalid_request"})
		return
	}
	if err := validateRequest(req); err != nil {
		_ = writeResponse(conn, Response{RequestID: strings.TrimSpace(req.RequestID), OK: false, Code: "invalid_request"})
		return
	}

	code := ProtocolCodeOK
	if err := runChpasswd(req.Username, req.NewPassword, cfg.CommandTimeout); err != nil {
		code = ProtocolCodeError
	}
	log.Printf("pam_reset_helper request_id=%s username=%s result_code=%s", safeLogValue(req.RequestID), safeLogValue(req.Username), code)
	if code != ProtocolCodeOK {
		_ = writeResponse(conn, Response{RequestID: req.RequestID, OK: false, Code: code})
		return
	}
	_ = writeResponse(conn, Response{RequestID: req.RequestID, OK: true, Code: ProtocolCodeOK})
}

func validateRequest(req Request) error {
	if strings.TrimSpace(req.RequestID) == "" {
		return fmt.Errorf("request_id is required")
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if len([]byte(username)) > MaxUsernameBytes {
		return fmt.Errorf("username exceeds limit")
	}
	if len([]byte(req.NewPassword)) == 0 {
		return fmt.Errorf("new_password is required")
	}
	if len([]byte(req.NewPassword)) > MaxPasswordBytes {
		return fmt.Errorf("new_password exceeds limit")
	}
	return nil
}

func runChpasswd(username, password string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	payload := []byte(strings.TrimSpace(username) + ":" + password + "\n")
	defer zero(payload)

	cmd := exec.CommandContext(ctx, "/usr/sbin/chpasswd")
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func authorizePeer(conn net.Conn, cfg HelperConfig) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unix socket required")
	}
	uid, gid, err := peerCredentials(uc)
	if err != nil {
		return err
	}
	if cfg.AllowedUID >= 0 && uid != cfg.AllowedUID {
		return fmt.Errorf("uid %d is not allowed", uid)
	}
	if cfg.AllowedGID >= 0 && gid != cfg.AllowedGID {
		return fmt.Errorf("gid %d is not allowed", gid)
	}
	return nil
}

func writeResponse(conn net.Conn, resp Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return writeFrame(conn, payload)
}

func readFrame(r io.Reader, maxLen int) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || int(n) > maxLen {
		return nil, fmt.Errorf("invalid frame length")
	}
	out := make([]byte, int(n))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFrameSize {
		return fmt.Errorf("invalid payload length")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func filepathDir(path string) string {
	if path == "" {
		return "."
	}
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return "."
	}
	return path[:lastSlash]
}

func safeLogValue(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, trimmed)
}
