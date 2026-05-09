package accesslog_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	alsdata "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestServerStreamAccessLogs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "stats.db")
	socket := filepath.Join(dir, "als.sock")

	store, err := eventstore.Open(t.Context(), dbPath,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	srv, err := accesslog.Start(t.Context(), socket, store)
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		srv.Shutdown(ctx)
	})

	conn, err := grpc.NewClient("unix:"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "unix", socket)
		}),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, conn.Close()) })

	client := als.NewAccessLogServiceClient(conn)

	stream, err := client.StreamAccessLogs(t.Context())
	require.NoError(t, err)

	err = stream.Send(&als.StreamAccessLogsMessage{
		Identifier: &als.StreamAccessLogsMessage_Identifier{
			LogName: "http_forward",
			Node:    &corev3.Node{Id: "test-envoy"},
		},
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*alsdata.HTTPAccessLogEntry{
					{
						CommonProperties: &alsdata.AccessLogCommon{},
						Request: &alsdata.HTTPRequestProperties{
							Authority: "wired.example",
						},
						Response: &alsdata.HTTPResponseProperties{
							ResponseCode: wrapperspb.UInt32(200),
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	// Need the server's writer goroutine to drain the channel.
	require.Eventually(t, func() bool {
		db, err := eventstore.OpenReadOnly(dbPath)
		if err != nil {
			return false
		}

		defer db.Close()

		var n int

		_ = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)

		return n == 1
	}, 2*time.Second, 20*time.Millisecond)

	_, _ = stream.CloseAndRecv()

	// Verify the event details.
	db, err := eventstore.OpenReadOnly(dbPath)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	var (
		source, decision, domain string
		status                   int
	)

	err = db.QueryRow(`SELECT source, decision, domain, http_status FROM events LIMIT 1`).
		Scan(&source, &decision, &domain, &status)
	require.NoError(t, err)

	assert.Equal(t, "envoy", source)
	assert.Equal(t, "allow", decision)
	assert.Equal(t, "wired.example", domain)
	assert.Equal(t, 200, status)
}
