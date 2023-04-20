package selfcert_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gopatchy/selfcert"
	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	t.Parallel()

	conf, err := selfcert.NewTLSConfigFromHostPort("localhost:0")
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "localhost:0", conf)
	require.NoError(t, err)

	baseURL := fmt.Sprintf("https://localhost:%d/", listener.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{
		ReadHeaderTimeout: 1 * time.Second,
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	cli := resty.New()
	cli.SetBaseURL(baseURL)
	cli.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
	})

	resp, err := cli.R().Get("/")
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Equal(t, resp.StatusCode(), 404)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}
