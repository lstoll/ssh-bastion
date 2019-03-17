package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/lstoll/nassh-relay"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sshProxy can be used to dial a backend SSH server.
type sshProxy struct {
	l              logrus.FieldLogger
	hostKey        ssh.Signer
	clientKey      ssh.Signer
	clientUsername string
}

func (s *sshProxy) Dial(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	uid, uok := nassh.UserID(ctx)
	lid, lok := nassh.LoginSessionID(ctx)
	sid, sok := nassh.SSHSessionID(ctx)
	raddr, rok := nassh.RemoteAddr(ctx)
	if !uok || !lok || !sok || !rok {
		return nil, errors.New("Context missing expected information")
	}
	l := s.l.WithFields(logrus.Fields{
		"user":          uid,
		"login-session": lid,
		"ssh-session":   sid,
		"remote":        raddr,
		"addr":          addr,
	})
	// l := s.l.WithField("user", uid).WithField("remote", req.RemoteAddr).WithField("addr", addr).WithF
	l.Info("Dialing new backend")

	// we need a pipe for client writing to server, and server writing to client
	cliReader, srvWriter := io.Pipe()
	srvReader, cliWriter := io.Pipe()

	inc := &netConn{srvReader, srvWriter, raddr}

	ssc := &ssh.ServerConfig{
		NoClientAuth: true, // We auth via the HTTP flow
	}
	ssc.AddHostKey(s.hostKey)

	go func() {
		// Run this all in a goroutine as this needs to negotiate with the
		// client, which means we need to returned. Practically this is the
		// equivalent of a normal Dial.
		sconn, chans, reqs, err := ssh.NewServerConn(inc, ssc)
		if err != nil {
			l.WithError(err).Info("Error creating new SSH server connection")
			return
		}

		go ssh.DiscardRequests(reqs)

		nchan := <-chans
		if nchan == nil {
			inc.Close()
			l.Error("No channel returned")
		}

		switch nchan.ChannelType() {
		case "session":
			if err := s.SessionForward(l, sconn, nchan, chans, addr); err != nil {
				l.WithError(err).Error("Error forwarding session")
			}
		default:
			nchan.Reject(ssh.UnknownChannelType, "connection flow not supported, only interactive sessions are permitted.")
		}

		sconn.Close()
		inc.Close()
	}()

	return &pipeRWC{cliReader, cliWriter}, nil
}

// SessionForward performs a regular forward, providing the user with an
// interactive remote host selection if necessary. This forwarding type
// requires agent forwarding in order to work.
func (s *sshProxy) SessionForward(l logrus.FieldLogger, sconn *ssh.ServerConn, newChannel ssh.NewChannel, chans <-chan ssh.NewChannel, destAddr string) error {
	sesschan, sessReqs, err := newChannel.Accept()
	if err != nil {
		return err
	}

	stderr := sesschan.Stderr()

	fmt.Fprintf(stderr, "Establishing connection to remote server %s...\r\n", destAddr)

	// Set up the client

	clientConfig := &ssh.ClientConfig{
		User: s.clientUsername,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.clientKey),
		},
		HostKeyCallback: func(hostname string, addr net.Addr, key ssh.PublicKey) error {
			// TODO - it would be ideal to use say vault's SSH host key signing
			// as well, or at least some way to track thi.
			fmt.Fprintf(stderr, "Remote server has host key %s, we're not verifying tho\r\n", ssh.FingerprintSHA256(key))
			return nil
		},
	}

	// Process requests. Check them first to see if we have an agent request
	// already, if so handle it so we can use it to auth to the remote server.
	// Otherwise drop agent requests, they represent a security risk for the
	// remote machine
	var agentEnabled bool
	maskedReqs := make(chan *ssh.Request, 10)
	handleReq := func(req *ssh.Request) {
		if req.Type == "auth-agent-req@openssh.com" {
			agentEnabled = true
		} else {
			maskedReqs <- req
		}
	}
	for i := 0; i < 10; i++ {
		select {
		case req := <-sessReqs:
			handleReq(req)
		default:
		}
	}
	// Now we've read the initial batch, handle the ongoings
	go func() {
		for req := range sessReqs {
			handleReq(req)
		}
	}()

	if agentEnabled {
		agentChan, agentReqs, err := sconn.OpenChannel("auth-agent@openssh.com", nil)
		if err != nil {
			return err
		}

		defer agentChan.Close()
		go ssh.DiscardRequests(agentReqs)

		ag := agent.NewClient(agentChan)
		clientConfig.Auth = append([]ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}, clientConfig.Auth...)
	}

	client, err := ssh.Dial("tcp", destAddr, clientConfig)
	if err != nil {
		fmt.Fprintf(stderr, "Connect failed: %v\r\n", err)
		sesschan.Close()
		return err
	}

	// Handle all incoming channel requests
	go func() {
		for newChannel = range chans {
			if newChannel == nil {
				return
			}

			channel2, reqs2, err := client.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err != nil {
				x, ok := err.(*ssh.OpenChannelError)
				if ok {
					newChannel.Reject(x.Reason, x.Message)
				} else {
					newChannel.Reject(ssh.Prohibited, "remote server denied channel request")
				}
				continue
			}

			channel, reqs, err := newChannel.Accept()
			if err != nil {
				channel2.Close()
				continue
			}
			go proxy(reqs, reqs2, channel, channel2)
		}
	}()

	// Forward the session channel
	channel2, reqs2, err := client.OpenChannel("session", []byte{})
	if err != nil {
		fmt.Fprintf(stderr, "Remote session setup failed: %v\r\n", err)
		sesschan.Close()
		return err
	}

	proxy(maskedReqs, reqs2, sesschan, channel2)
	return nil
}

func proxy(reqs1, reqs2 <-chan *ssh.Request, channel1, channel2 ssh.Channel) {
	var closer sync.Once
	closeFunc := func() {
		channel1.Close()
		channel2.Close()
	}

	defer closer.Do(closeFunc)

	closerChan := make(chan bool, 1)

	go func() {
		io.Copy(channel1, channel2)
		closerChan <- true
	}()

	go func() {
		io.Copy(channel2, channel1)
		closerChan <- true
	}()

	for {
		select {
		case req := <-reqs1:
			if req == nil {
				return
			}
			b, err := channel2.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)

		case req := <-reqs2:
			if req == nil {
				return
			}
			b, err := channel1.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}
