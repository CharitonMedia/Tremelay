package main

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// scriptedListener fails Accept `fails` times, then yields `conns`
// connections, then reports closure. fails < 0 fails forever.
type scriptedListener struct {
	fails, conns int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	if l.fails != 0 {
		if l.fails > 0 {
			l.fails--
		}
		return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
	}
	if l.conns == 0 {
		return nil, net.ErrClosed
	}
	l.conns--
	server, client := net.Pipe()
	client.Close()
	return server, nil
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return nil }

// TestAcceptLoopOutlivesTransientErrors is the regression test for a daemon
// that stopped accepting on its first Accept error (file descriptors ran out)
// and then sat unlocked behind an endpoint `tremelay lock` could not reach.
func TestAcceptLoopOutlivesTransientErrors(t *testing.T) {
	served := 0
	err := acceptLoop(context.Background(), &scriptedListener{fails: 3, conns: 2}, time.Minute, func(c net.Conn) {
		served++
		c.Close()
	})
	if err != nil || served != 2 {
		t.Fatalf("after 3 failed accepts: served=%d err=%v, want 2 served and a clean close", served, err)
	}
}

func TestAcceptLoopReportsDeadEndpoint(t *testing.T) {
	err := acceptLoop(context.Background(), &scriptedListener{fails: -1}, 20*time.Millisecond, func(net.Conn) {
		t.Error("a failing listener produced a connection")
	})
	if err != errAcceptDead {
		t.Fatalf("endpoint that never accepts: %v, want errAcceptDead", err)
	}
}

func TestAcceptLoopStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acceptLoop(ctx, &scriptedListener{fails: -1}, time.Minute, func(net.Conn) {}); err != nil {
		t.Fatalf("shutdown reported as a dead endpoint: %v", err)
	}
}
