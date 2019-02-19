package nassh

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const maxMessageLength = 32 * 1024
const headerLength = 4

// posMask specifies the maximum ACK value before wrapping
// See: https://chromium.googlesource.com/apps/libapps/+/master/nassh/doc/relay-protocol.md#writes
const posMask = 1<<24 - 1

// TODO: Decide on an appropriate buffer size
const bufferSize = 1 * 1024 * 1024 * 1024

type client struct {
	ws *websocket.Conn

	// ack is the last READ_ACK the client has received, or 0 for new
	// connections
	ack int
	// pos is the last WRITE_ACK the client has received, or 0 for new
	// connections
	pos int

	// closedCh is closed when the client is disconnected
	closedCh chan struct{}
}

func newClient(ws *websocket.Conn, ack, pos int) *client {
	return &client{
		ws:  ws,
		ack: ack,
		pos: pos,

		closedCh: make(chan struct{}),
	}
}

func (c *client) Write(p []byte) error {
	w, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return errors.Wrap(err, "error getting next client writer")
	}
	if err := binary.Write(w, binary.BigEndian, int32(c.pos)); err != nil {
		return errors.Wrap(err, "error writing header to client")
	}
	_, err = w.Write(p)
	if err != nil {
		return errors.Wrap(err, "error writing to client")
	}
	if err := w.Close(); err != nil {
		return errors.Wrap(err, "error closing client message")
	}
	return nil
}

func (c *client) Catchup(buf *buffer) error {
	pos := c.ack
	for {
		data := make([]byte, maxMessageLength-headerLength)
		n, npos, err := buf.Read(pos, data)
		if err != nil {
			return err
		} else if n == 0 {
			break
		}
		pos = npos

		if err := c.Write(data[:n]); err != nil {
			return err
		}
	}
	return nil
}

// Join waits until the client has been closed
func (c *client) Join() {
	_ = <-c.closedCh
}

func (c *client) Close() error {
	defer close(c.closedCh)
	return c.ws.Close()
}

type serverRead struct {
	buf []byte
}

type clientRead struct {
	ack int
	buf []byte
}

type session struct {
	logger logrus.FieldLogger
	// conn is the connection to the SSH server
	conn net.Conn

	sessID string

	// clientCh receives new client connections
	clientCh chan *client

	// closedCh is closed when the session is closed
	closedCh chan struct{}
	// closedLock ensures the session can only be closed a single time
	closedLock sync.Mutex
	// closed is set to true when the session is closed. Readers and writers
	// must hold closedLock.
	closed bool
}

func newSession(logger logrus.FieldLogger, conn net.Conn) *session {
	s := &session{
		logger:   logger,
		conn:     conn,
		sessID:   uuid.New().String(), // todo - more secure + unique
		clientCh: make(chan *client),
		closedCh: make(chan struct{}),
	}
	go s.loop()

	return s
}

func (s *session) Close() {
	s.closedLock.Lock()
	defer s.closedLock.Unlock()

	if s.closed {
		// already closed
		return
	}

	_ = s.conn.Close()
	s.closed = true
	close(s.closedCh)
}

func (s *session) IsClosed() bool {
	s.closedLock.Lock()
	defer s.closedLock.Unlock()

	return s.closed
}

func (s *session) loop() {
	serverReadCh := make(chan serverRead)
	go s.serverReadLoop(serverReadCh)

	buf := newBuffer(bufferSize, posMask)
	var currentClient *client
	var clientReadCh chan clientRead
	for {
		select {
		case newClient := <-s.clientCh:
			// Close out any existing client
			if currentClient != nil {
				currentClient.Close()
				currentClient = nil
				clientReadCh = nil
			}
			currentClient = newClient

			// Send the client any reads it missed. This can happen either when:
			// 1. There was a small delay between when we connected to the server
			// and when the client websocket connected. In that time, the server
			// sent the initial handshake.
			//
			// 2. The client is resuming a connection and while it was
			// disconnected, the server sent some data.
			if err := currentClient.Catchup(buf); err != nil {
				s.logger.WithError(err).Error("error writing to client")
				currentClient.Close()
				currentClient = nil
				clientReadCh = nil
				continue
			}

			clientReadCh = make(chan clientRead)
			go s.clientReadLoop(currentClient, clientReadCh)
		case r, ok := <-serverReadCh:
			if !ok {
				// The server read loop exited, meaning the server connection can
				// no longer be read.
				s.Close()
				continue
			}

			_, _, err := buf.Write(r.buf)
			if err != nil {
				// The only possible error from this buffer write is a buffer
				// overflow, meaning there's no client connected and the buffer
				// filled up. There's no way to recover from this, so tear
				// everything down.
				s.logger.WithError(err).Error("error writing to buffer")
				s.Close()
				continue
			}

			if currentClient != nil {
				if err := currentClient.Write(r.buf); err != nil {
					// Write failed. Disconnect the client. If the client supports
					// resumes, the data in the buffer will be used to catch up the
					// the reconnected client.
					s.logger.WithError(err).Error("error writing to client")
					currentClient.Close()
					currentClient = nil
					clientReadCh = nil
				}
			}
		case r, ok := <-clientReadCh:
			if !ok {
				// The client read loop exited, meaning the client connection can
				// no longer be read.
				currentClient.Close()
				currentClient = nil
				clientReadCh = nil
				continue
			}

			if err := buf.DiscardBefore(r.ack); err != nil {
				// The client sent some bogus ack value. Disconnect them.
				s.logger.WithError(err).Error("bogus ack")
				currentClient.Close()
				currentClient = nil
				clientReadCh = nil
				continue
			}

			currentClient.ack = r.ack
			currentClient.pos = (currentClient.pos + len(r.buf)) & posMask

			if _, err := s.conn.Write(r.buf); err != nil {
				s.logger.WithError(err).Error("error writing to server")
				s.Close()
			}
		case <-s.closedCh:
			// The entire session is shutting down. Disconnect any connected
			// client and exit the loop.
			if currentClient != nil {
				currentClient.Close()
				currentClient = nil
				clientReadCh = nil
			}

			break
		}
	}
}

func (s *session) serverReadLoop(readCh chan<- serverRead) {
	defer close(readCh)

	for {
		b := make([]byte, maxMessageLength)

		n, err := s.conn.Read(b)
		if err != nil {
			s.logger.WithError(err).Warn("error reading from server")
			break
		}

		select {
		case readCh <- serverRead{b[:n]}:
			continue
		case <-s.closedCh:
			break
		}
	}
}

func (s *session) clientReadLoop(c *client, readCh chan<- clientRead) {
	defer close(readCh)

	for {
		_, r, err := c.ws.NextReader()
		if err != nil {
			s.logger.WithError(err).Warn("error getting client reader")
			break
		}

		data := make([]byte, maxMessageLength)
		n, err := r.Read(data)
		if err != nil {
			s.logger.WithError(err).Warn("error reading from client")
			break
		} else if n < headerLength {
			s.logger.WithError(err).Warn("client read too short")
			break
		}
		data = data[:n]

		var ack int32
		if err := binary.Read(bytes.NewReader(data[:headerLength]), binary.BigEndian, &ack); err != nil {
			s.logger.WithError(err).Warn("error decoding client message header")
			break
		}

		// TODO: Ack over 0xffffff means error

		select {
		case readCh <- clientRead{int(ack), data[headerLength:]}:
			continue
		case <-c.closedCh:
			break
		}
	}
}

func (s *session) Run(ws *websocket.Conn, ack int, pos int) {
	client := newClient(ws, ack, pos)
	select {
	case s.clientCh <- client:
		client.Join()
	case <-s.closedCh:
		client.Close()
	}
}
