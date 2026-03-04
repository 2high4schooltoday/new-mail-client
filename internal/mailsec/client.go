package mailsec

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	DefaultMaxFrameSize = 8 * 1024 * 1024
)

type Client struct {
	socketPath   string
	maxFrameSize int
}

func NewClient(socketPath string) *Client {
	return &Client{
		socketPath:   socketPath,
		maxFrameSize: DefaultMaxFrameSize,
	}
}

func (c *Client) SetMaxFrameSize(n int) {
	if n <= 0 {
		return
	}
	c.maxFrameSize = n
}

func (c *Client) Call(ctx context.Context, req Request) (Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if len(payload) == 0 || len(payload) > c.maxFrameSize {
		return Response{}, fmt.Errorf("mailsec request frame exceeds size limits")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(payload); err != nil {
		return Response{}, err
	}

	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return Response{}, err
	}
	respLen := int(binary.BigEndian.Uint32(lenBuf))
	if respLen <= 0 || respLen > c.maxFrameSize {
		return Response{}, fmt.Errorf("mailsec response frame exceeds size limits")
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return Response{}, err
	}
	var out Response
	if err := json.Unmarshal(buf, &out); err != nil {
		return Response{}, err
	}
	return out, nil
}
