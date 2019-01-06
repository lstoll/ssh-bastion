package nassh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/oklog/run"
	"github.com/pkg/errors"
)

type session struct {
	sessID string
	// connection to the backend
	conn net.Conn
	// last read received by server
	ack int32
	// last write received by client
	pos int32
}

// newSession creates a new session to the provided backend. If it successfully
// connects, a session will be returned. this should be closed when done with.
func newSession(addr string) (*session, error) {
	// https://github.com/clefru/nassh-relay/blob/b0bc10e/nassh-relay.js#L143-L180

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, errors.Wrap(err, "Error establishing connection to backend")
	}

	// Start a read loop on conn, appending to retrans and sending to ws if it's
	// non-nil

	return &session{
		sessID: uuid.New().String(), // todo - more secure + unique
		conn:   conn,
	}, nil
}

// Close shuts down the
func (s *session) Close() error {
	return s.conn.Close()
}

func (s *session) Run(ws *websocket.Conn) error {
	// TODO - only permit one run to be running at a time
	stopClient := make(chan struct{})
	stopServer := make(chan struct{})

	var g run.Group

	g.Add(func() error {
		return s.fromClient(ws, stopClient)
	}, func(err error) {
		stopClient <- struct{}{}
	})

	g.Add(func() error {
		return s.fromServer(ws, stopServer)
	}, func(err error) {
		stopServer <- struct{}{}
	})

	return g.Run()
}

func (s *session) fromClient(ws *websocket.Conn, stopCh chan struct{}) error {
	for {
		select {
		case <-stopCh:
			// TODO - cleanup?
			return nil
		default:
			_, r, err := ws.NextReader()
			if err != nil {
				return errors.Wrap(err, "Error getting client reader")
			}
			hdr := make([]byte, 4)
			_, err = r.Read(hdr)
			if err != nil {
				return errors.Wrap(err, "Error reading header from client")
			}
			var pos int32
			if err := binary.Read(bytes.NewBuffer(hdr), binary.BigEndian, &pos); err != nil {
				return errors.Wrap(err, "Error finding client position")
			}
			wb, err := io.Copy(s.conn, r)
			if err != nil {
				return errors.Wrap(err, "Error copying data from client to backend")
			}
			_ = wb // wb
			atomic.AddInt32(&s.pos, pos)
		}
	}
}

func (s *session) fromServer(ws *websocket.Conn, stopCh chan struct{}) error {
	for {
		select {
		case <-stopCh:
			// TODO - cleanup?
			return nil
		default:
			w, err := ws.NextWriter(websocket.BinaryMessage)
			if err != nil {
				return errors.Wrap(err, "Error getting client writer")
			}
			data := make([]byte, 4096)
			n, err := s.conn.Read(data)
			if err != nil {
				return errors.Wrap(err, "Error reading from connection")
			}
			// WRITE HEADER
			if err := binary.Write(w, binary.BigEndian, int32(0)); err != nil {
				return errors.Wrap(err, "Error writing header to client")

			}
			n, err = w.Write(data[:n])
			if err != nil {
				return errors.Wrap(err, "Error writing to client")
			}
		}
	}
}
