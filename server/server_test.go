package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

type drainer struct{ at atomic.Int64 }

func (d *drainer) Drain() { d.at.Store(time.Now().UnixNano()) }

// SIGTERM: drain first, keep answering during the drain, let an in-flight request finish.
func TestGracefulShutdown(t *testing.T) {
	addr := freeAddr(t)
	slow := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-slow
		}
		_, _ = io.WriteString(w, "ok")
	})
	d := &drainer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Servers: []*http.Server{New(addr, h, quiet())}, Drainer: d,
			Drain: 300 * time.Millisecond, ShutdownTimeout: 2 * time.Second}, quiet())
	}()
	waitUp(t, addr)

	inflight := make(chan string, 1)
	go func() {
		res, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			inflight <- err.Error()
			return
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		inflight <- string(b)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)
	if d.at.Load() == 0 {
		t.Fatal("not drained on shutdown")
	}
	if res, err := http.Get("http://" + addr + "/"); err != nil || res.StatusCode != 200 {
		t.Fatalf("must keep answering during the drain: %v", err)
	}
	close(slow)
	if got := <-inflight; got != "ok" {
		t.Fatalf("in-flight request: %s", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get("http://" + addr + "/"); err == nil {
		t.Fatal("still serving after Run returned")
	}
}

func TestPortTakenFailsStartUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	free := freeAddr(t)
	err = Run(context.Background(), Config{Servers: []*http.Server{
		New(free, http.NotFoundHandler(), quiet()), New(ln.Addr().String(), http.NotFoundHandler(), quiet()),
	}}, quiet())
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("got %v", err)
	}
	// The free port was released again.
	if l, err := net.Listen("tcp", free); err != nil {
		t.Fatalf("port left bound: %v", err)
	} else {
		l.Close()
	}
}

func TestFailingTaskStopsTheService(t *testing.T) {
	boom := func(context.Context) error { return io.ErrUnexpectedEOF }
	err := Run(context.Background(), Config{Servers: []*http.Server{New(freeAddr(t), http.NotFoundHandler(), quiet())},
		Background: []func(context.Context) error{boom}}, quiet())
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("got %v", err)
	}
}

func waitUp(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server never came up")
}
