// Package pop3d implements an POP3 server 
package pop3d

import (
  "bufio"
  "crypto/tls"
  "fmt"
  "log"
  "net"
  "time"
)

// Server defines the parameters for running the POP3 server
type Server struct {
  Hostname       string // Server hostname. (default: "localhost.localdomain")
  WelcomeMessage string // Initial server banner. (default: "<hostname> POP3 ready.")

  ReadTimeout  time.Duration // Socket timeout for read operations. (default: 60s)
  WriteTimeout time.Duration // Socket timeout for write operations. (default: 60s)
  DataTimeout  time.Duration // Socket timeout for DATA command (default: 5m)

  MaxConnections int // Max concurrent connections, use -1 to disable. (default: 100)
  MaxMessageSize int // Max message size in bytes. (default: 10240000)
  MaxRecipients  int // Max RCPT TO calls for each envelope. (default: 100)

  // New e-mails are handed off to this function.
  // Can be left empty for a NOOP server.
  // If an error is returned, it will be reported in the POP3 session.
  //Handler func(peer Peer, env Envelope) error

  // Enable various checks during the POP3 session.
  // Can be left empty for no restrictions.
  // If an error is returned, it will be reported in the POP3 session.
  // Use the Error struct for access to error codes.
  ConnectionChecker func(peer Peer) error              // Called upon new connection.
  HeloChecker       func(peer Peer, name string) error // Called after HELO/EHLO.
  SenderChecker     func(peer Peer, addr string) error // Called after MAIL FROM.
  RecipientChecker  func(peer Peer, addr string) error // Called after each RCPT TO.

  // Enable PLAIN/LOGIN authentication, only available after STARTTLS.
  // Can be left empty for no authentication support.
  Authenticator func(peer Peer, username, password string) bool

  EnableProxyProtocol bool // Enable proxy protocol support (default: false)

  TLSConfig *tls.Config // Enable STARTTLS support.
  ForceTLS  bool        // Force STARTTLS usage.

}

// Protocol represents the protocol used in the POP3 session
type Protocol string

const (
  // POP3
  POP3 Protocol = "POP3"
)

// Peer represents the client connecting to the server
type Peer struct {
  HeloName        string               // Server name used in HELO/EHLO command
  Username        string               // Username from authentication, if authenticated
  Password        string               // Password from authentication, if authenticated
  Protocol        Protocol             // Protocol used, POP3 or EPOP3
  ServerName      string               // A copy of Server.Hostname
  Addr            net.Addr             // Network address
  TLS             *tls.ConnectionState // TLS Connection details, if on TLS
  Authenticated   bool                 // True is authenticated, False if not.
  LoopCheck       []string             // Array to hold DNS infinite lookup loop redirects. And to check against in lookups.
}

// Error represents an Error reported in the POP3 session.
type Error struct {
  Code    int    // The integer error code
  Message string // The error message
}

// Error returns a string representation of the POP3 error
func (e Error) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Message) }

type session struct {
  server *Server

  peer     Peer

  conn net.Conn

  reader  *bufio.Reader
  writer  *bufio.Writer
  scanner *bufio.Scanner

  tls bool
}

func (srv *Server) newSession(c net.Conn) (s *session) {

  s = &session{
    server: srv,
    conn:   c,
    reader: bufio.NewReader(c),
    writer: bufio.NewWriter(c),
    peer: Peer{
      Addr:       c.RemoteAddr(),
      ServerName: srv.Hostname,
    },
  }

  // Check if the underlying connection is already TLS.
  // This will happen if the Listerner provided Serve()
  // is from tls.Listen()

  var tlsConn *tls.Conn

  tlsConn, s.tls = c.(*tls.Conn)

  if s.tls {
    // run handshake otherwise it's done when we first
    // read/write and connection state will be invalid
    tlsConn.Handshake()
    state := tlsConn.ConnectionState()
    s.peer.TLS = &state
  }

  s.scanner = bufio.NewScanner(s.reader)

  return

}

// ListenAndServe starts the POP3 server and listens on the address provided
func (srv *Server) ListenAndServe(addr string) error {

  srv.configureDefaults()

  l, err := net.Listen("tcp", addr)
  if err != nil {
    return err
  }

  return srv.Serve(l)
}

// Serve starts the POP3 server and listens on the Listener provided
func (srv *Server) Serve(l net.Listener) error {

  srv.configureDefaults()

  defer l.Close()

  var limiter chan struct{}

  if srv.MaxConnections > 0 {
    limiter = make(chan struct{}, srv.MaxConnections)
  } else {
    limiter = nil
  }

  for {

    conn, e := l.Accept()
    if e != nil {
      if ne, ok := e.(net.Error); ok && ne.Temporary() {
        time.Sleep(time.Second)
        continue
      }
      return e
    }

    session := srv.newSession(conn)

    if limiter != nil {
      go func() {
        select {
        case limiter <- struct{}{}:
          session.serve()
          <-limiter
        default:
          session.reject()
        }
      }()
    } else {
      go session.serve()
    }

  }

}

func (srv *Server) configureDefaults() {

  if srv.MaxMessageSize == 0 {
    srv.MaxMessageSize = 10240000
  }

  if srv.MaxConnections == 0 {
    srv.MaxConnections = 100
  }

  if srv.MaxRecipients == 0 {
    srv.MaxRecipients = 100
  }

  if srv.ReadTimeout == 0 {
    srv.ReadTimeout = time.Second * 60
  }

  if srv.WriteTimeout == 0 {
    srv.WriteTimeout = time.Second * 60
  }

  if srv.DataTimeout == 0 {
    srv.DataTimeout = time.Minute * 5
  }

  if srv.ForceTLS && srv.TLSConfig == nil {
    log.Fatal("Cannot use ForceTLS with no TLSConfig")
  }

  if srv.Hostname == "" {
    srv.Hostname = "localhost.localdomain"
  }

  if srv.WelcomeMessage == "" {
    srv.WelcomeMessage = fmt.Sprintf("%s POP3 ready.", srv.Hostname)
  }

}

func (session *session) serve() {

  defer session.close()

  if !session.server.EnableProxyProtocol {
    session.welcome()
  }

  for {

    for session.scanner.Scan() {
      line := session.scanner.Text()
      session.handle(line)
    }

    err := session.scanner.Err()

    if err == bufio.ErrTooLong {

      session.reply(500, "Line too long")

      // Advance reader to the next newline

      session.reader.ReadString('\n')
      session.scanner = bufio.NewScanner(session.reader)

      // Reset and have the client start over.

      session.reset()

      continue
    }

    break
  }

}

func (session *session) reject() {
  session.reply(421, "Too busy. Try again later.")
  session.close()
}

func (session *session) reset() {
  session = nil
}

func (session *session) welcome() {

  if session.server.ConnectionChecker != nil {
    err := session.server.ConnectionChecker(session.peer)
    if err != nil {
      session.error(err)
      session.close()
      return
    }
  }

  //if all good - issue welcome message
    session.reply(220, session.server.WelcomeMessage)
}

func (session *session) reply(code int, message string) {
  fmt.Fprintf(session.writer, "%d %s\r\n", code, message)
  session.flush()
}

func (session *session) flush() {
  session.conn.SetWriteDeadline(time.Now().Add(session.server.WriteTimeout))
  session.writer.Flush()
  session.conn.SetReadDeadline(time.Now().Add(session.server.ReadTimeout))
}

func (session *session) error(err error) {
  if pop3dError, ok := err.(Error); ok {
    session.reply(pop3dError.Code, pop3dError.Message)
  } else {
    session.reply(502, fmt.Sprintf("%s", err))
  }
}

func (session *session) logError(err error, desc string) {
}

func (session *session) extensions() []string {

  extensions := []string{
    fmt.Sprintf("SIZE %d", session.server.MaxMessageSize),
    "8BITMIME",
    "PIPELINING",
  }

  if session.server.TLSConfig != nil && !session.tls {
    extensions = append(extensions, "STARTTLS")
  }

  if session.server.Authenticator != nil && session.tls {
    extensions = append(extensions, "AUTH PLAIN LOGIN")
  }

  return extensions

}

func (session *session) close() {
  session.writer.Flush()
  time.Sleep(200 * time.Millisecond)
  session.conn.Close()
}
