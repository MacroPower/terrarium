package accesslog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// Option configures optional behavior of a [Server].
//
// The following options are available:
//
//   - [WithLogger]
//   - [WithSocketMode]
//   - [WithSocketOwner]
type Option func(*serverOptions)

// serverOptions holds resolved values configured by [Option] funcs.
type serverOptions struct {
	logger         *slog.Logger
	socketMode     os.FileMode
	socketOwnerUID int
}

// defaultServerOptions returns the option set used when [Start] is
// called without explicit options.
func defaultServerOptions() serverOptions {
	return serverOptions{
		logger:         slog.Default(),
		socketMode:     0o660,
		socketOwnerUID: -1,
	}
}

// WithLogger sets the logger used for diagnostic messages. An [Option].
func WithLogger(l *slog.Logger) Option {
	return func(o *serverOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithSocketMode overrides the default 0o660 socket file mode. An
// [Option].
func WithSocketMode(m os.FileMode) Option {
	return func(o *serverOptions) {
		o.socketMode = m
	}
}

// WithSocketOwner chowns the socket file to uid:uid after bind so a
// non-root Envoy can connect. Negative values disable chowning. An
// [Option].
func WithSocketOwner(uid int) Option {
	return func(o *serverOptions) {
		o.socketOwnerUID = uid
	}
}

// Server is a long-lived gRPC AccessLog Service over a Unix domain
// socket. Envoy connects, opens a stream, and pushes HTTPAccessLogEntry
// or TCPAccessLogEntry messages. Each entry becomes one
// [eventstore.Event].
//
// Create instances with [Start].
type Server struct {
	grpc   *grpc.Server
	logger *slog.Logger
	socket string

	wg sync.WaitGroup
}

// Start binds socket as a Unix listener, sets the file mode so Envoy
// can connect, registers an [als.AccessLogServiceServer], and serves
// in a background goroutine. The returned [*Server] runs until
// [Server.Shutdown] or the listener is closed.
//
// If binding or chmod fails, Start returns the error and the caller
// should log and continue without ingestion.
func Start(ctx context.Context, socket string, store *eventstore.Store, opts ...Option) (*Server, error) {
	o := defaultServerOptions()
	for _, opt := range opts {
		opt(&o)
	}

	err := os.MkdirAll(filepath.Dir(socket), 0o755)
	if err != nil {
		return nil, fmt.Errorf("creating socket dir: %w", err)
	}

	// Remove a stale socket file from a previous crash.
	err = os.Remove(socket)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}

	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", socket, err)
	}

	err = os.Chmod(socket, o.socketMode)
	if err != nil {
		_ = ln.Close() //nolint:errcheck // abandoning listener on setup error; original error is returned.

		return nil, fmt.Errorf("chmod %s: %w", socket, err)
	}

	if o.socketOwnerUID >= 0 {
		err = os.Chown(socket, o.socketOwnerUID, o.socketOwnerUID)
		if err != nil {
			_ = ln.Close() //nolint:errcheck // abandoning listener on setup error; original error is returned.

			return nil, fmt.Errorf("chown %s: %w", socket, err)
		}
	}

	// Permit Envoy keepalives at the documented 30s default; without
	// this, gRPC's default policy (ping no more than every 5min) would
	// terminate the stream with GOAWAY and force a reconnect.
	gs := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second,
		PermitWithoutStream: true,
	}))
	als.RegisterAccessLogServiceServer(gs, &accessLogService{
		store:  store,
		logger: o.logger,
	})

	s := &Server{
		grpc:   gs,
		logger: o.logger,
		socket: socket,
	}

	s.wg.Go(func() {
		err := gs.Serve(ln)
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, grpc.ErrServerStopped) {
			o.logger.WarnContext(ctx, "accesslog grpc server exited", slog.Any("err", err))
		}
	})

	return s, nil
}

// Shutdown gracefully stops the gRPC server. The ctx deadline caps
// how long to wait before forcing a stop. The socket file is removed
// so a later [Start] does not see a stale entry.
func (s *Server) Shutdown(ctx context.Context) {
	if s == nil {
		return
	}

	done := make(chan struct{})

	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		s.grpc.Stop()
	}

	s.wg.Wait()

	err := os.Remove(s.socket)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.DebugContext(ctx, "removing accesslog socket", slog.Any("err", err))
	}
}

// accessLogService is the gRPC server implementation. Each long-lived
// stream produces [als.StreamAccessLogsMessage] values; entries within
// each message are translated and emitted.
type accessLogService struct {
	als.UnimplementedAccessLogServiceServer

	store  *eventstore.Store
	logger *slog.Logger
}

// StreamAccessLogs is the gRPC handler. It loops on the stream until
// the client disconnects or the server context is canceled.
func (s *accessLogService) StreamAccessLogs(stream als.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			err = stream.SendAndClose(&als.StreamAccessLogsResponse{})
			if err != nil {
				return fmt.Errorf("closing access log stream: %w", err)
			}

			return nil
		}

		if err != nil {
			return fmt.Errorf("receiving access log message: %w", err)
		}

		s.handleMessage(msg)
	}
}

// handleMessage translates each entry in msg into an [eventstore.Event]
// and emits it.
func (s *accessLogService) handleMessage(msg *als.StreamAccessLogsMessage) {
	if http := msg.GetHttpLogs(); http != nil {
		for _, entry := range http.GetLogEntry() {
			s.store.Emit(httpEntryToEvent(entry))
		}

		return
	}

	if tcp := msg.GetTcpLogs(); tcp != nil {
		for _, entry := range tcp.GetLogEntry() {
			s.store.Emit(tcpEntryToEvent(entry))
		}

		return
	}

	// Neither HttpLogs nor TcpLogs set. Either a future Envoy entry
	// kind or a malformed payload; log so version drift stays visible.
	s.logger.Debug("accesslog: stream message with no recognized entry kind",
		slog.String("log_name", msg.GetIdentifier().GetLogName()))
}
