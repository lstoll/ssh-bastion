package main

import (
	"io"
	"net"
	"time"
)

// netConn is a dummy net.Conn that represents the nassh client dialing. It
// wraps a io.ReadWriteCloser for a net.Conn the SSH server can accept
type netConn struct {
	cliReader  io.ReadCloser
	cliWriter  io.WriteCloser
	remoteAddr string
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (n *netConn) Read(b []byte) (int, error) {
	return n.cliReader.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (n *netConn) Write(b []byte) (int, error) {
	return n.cliWriter.Write(b)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (n *netConn) Close() error {
	if err := n.cliWriter.Close(); err != nil {
		return err
	}
	return n.cliReader.Close()
}

// LocalAddr returns the local network address.
func (n *netConn) LocalAddr() net.Addr {
	return &netaddr{"inprocess", "n/a"}
}

// RemoteAddr returns the remote network address.
func (n *netConn) RemoteAddr() net.Addr {
	return &netaddr{"tcp", n.remoteAddr}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (n *netConn) SetDeadline(t time.Time) error {
	return nil // TODO
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (n *netConn) SetReadDeadline(t time.Time) error {
	return nil // TODO
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (n *netConn) SetWriteDeadline(t time.Time) error {
	return nil // TODO
}

type netaddr struct {
	network string
	addr    string
}

func (a *netaddr) Network() string {
	return a.network

}
func (a *netaddr) String() string {
	return a.addr
}

type pipeRWC struct {
	cliReader io.ReadCloser
	cliWriter io.WriteCloser
}

func (p *pipeRWC) Read(b []byte) (int, error) {
	return p.cliReader.Read(b)
}

func (p *pipeRWC) Write(b []byte) (int, error) {
	return p.cliWriter.Write(b)
}

func (p *pipeRWC) Close() error {
	if err := p.cliWriter.Close(); err != nil {
		return err
	}
	return p.cliReader.Close()
}
