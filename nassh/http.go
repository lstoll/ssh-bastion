package nassh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const bsidLength = 16

// TODO: Determine or leave configurable
const inactivityDuration = 60 * time.Second

// https://chromium.googlesource.com/apps/libapps/+show/master/nassh/doc/relay-protocol.md

type Relay struct {
	Logger logrus.FieldLogger

	sessions   map[string]*session
	sessionsMu sync.Mutex
}

// SimpleCookieHandler simply starts the session and returns the user to the
// extension, with no authentication. Serve at /cookie
func (r *Relay) SimpleCookieHandler(w http.ResponseWriter, req *http.Request) {
	ext := req.URL.Query().Get("ext")
	path := req.URL.Query().Get("path")
	if ext == "" || path == "" {
		http.Error(w, "ext and path are required params", http.StatusBadRequest)
		return
	}
	version := req.URL.Query().Get("version")
	if version != "" && version != "2" {
		// TODO - we're not really supporting v2 properly
		http.Error(w, "only version 2 is supported", http.StatusBadRequest)
		return
	}
	method := req.URL.Query().Get("method")
	if method == "" {
		http.Redirect(w, req, fmt.Sprintf("chrome-extension://%s/%s#anonymous@%s", ext, path, req.Host), http.StatusFound)
	} else if method == "js-redirect" {
		fmt.Fprintf(w, "<script>window.location.href = \"chrome://%s/%s\";</script>", ext, path)
	} else {
		http.Error(w, "only js-redirect supported", http.StatusBadRequest)
		return
	}
	// TODO - render redir doc https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#147
}

// ProxyHandler starts the remote connection. Serve at /proxy
// https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#153
func (r *Relay) ProxyHandler(w http.ResponseWriter, req *http.Request) {
	host := req.URL.Query().Get("host")
	port := req.URL.Query().Get("port")
	if host == "" || port == "" {
		http.Error(w, "host and port are required params", http.StatusBadRequest)
		return
	}

	// TODO: Should probably make sure this is only port 22 on allowed hots
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.Logger.WithError(err).WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Warn("error establishing connection to server")

		http.Error(w, "error establishing connection to server", http.StatusInternalServerError)
		return
	}

	bsid := make([]byte, bsidLength)
	if _, err := rand.Read(bsid); err != nil {
		r.Logger.WithError(err).Error("error generating session ID")

		http.Error(w, "error generating session ID", http.StatusInternalServerError)
		return
	}
	sid := hex.EncodeToString(bsid)

	afterCloseFunc := func() {
		r.Logger.WithField("sid", sid).Info("closed")
		r.deleteSession(sid)
	}
	s := newSession(r.Logger.WithField("sid", sid), conn, inactivityDuration, afterCloseFunc)
	r.setSession(sid, s)
	s.Start()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// response is plain text, query string that will be passed to /connect
	fmt.Fprintf(w, "%s", sid)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ConnectHandler handles the /connect from the client
// https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#178
func (r *Relay) ConnectHandler(w http.ResponseWriter, req *http.Request) {
	// Find session
	sid := req.URL.Query().Get("sid")
	if sid == "" {
		http.Error(w, "no session id provided", http.StatusBadRequest)
		return
	}

	sess, ok := r.getSession(sid)
	if !ok {
		r.Logger.WithField("sid", sid).Warn("Session not found")
		http.Error(w, "no session found", http.StatusGone)
		return
	}

	c, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		r.Logger.WithError(err).WithField("sid", sid).Warn("Failed to upgrade session")
		http.Error(w, "Couldn't upgrade connection", http.StatusBadRequest)
		return
	}
	defer c.Close()

	ack, _ := strconv.Atoi(req.URL.Query().Get("ack"))
	pos, _ := strconv.Atoi(req.URL.Query().Get("pos"))

	sess.Serve(c, ack, pos)
}

func (r *Relay) getSession(sid string) (s *session, ok bool) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	s, ok = r.sessions[sid]
	return
}

func (r *Relay) setSession(sid string, s *session) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	if r.sessions == nil {
		r.sessions = map[string]*session{}
	}
	r.sessions[sid] = s
}

func (r *Relay) deleteSession(sid string) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	delete(r.sessions, sid)
}
