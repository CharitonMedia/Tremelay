//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func TestPinentryPrivateHelper(t *testing.T) {
	t.Setenv("TREMELAY_PASSPHRASE", randHex(t, 24))
	t.Setenv("TREMELAY_TEST_PRIVATE", randHex(t, 24))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want error
	}{
		{"success", nil}, {"cancel", errPinentryCancelled},
		{"malformed", errPinentryFailed}, {"hang", errPinentryTimeout},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tremelay-pinentry-test-"+tc.mode)
			if err := os.Symlink(executable, path); err != nil {
				t.Fatal(err)
			}
			timeout := 5 * time.Second
			if tc.mode == "hang" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			pass, err := readPinentry(ctx, pinentryOptions{path: path})
			defer vault.Wipe(pass)
			if !errors.Is(err, tc.want) || (err == nil && len(pass) != 24) || (err != nil && pass != nil) {
				t.Fatalf("helper result: length %d, error %v", len(pass), err)
			}
		})
	}
}

func TestMCPStdioCloseInterruptsPipes(t *testing.T) {
	in, clientWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	defer clientWrite.Close()
	clientRead, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer clientRead.Close()
	defer out.Close()
	s, err := openMCPStdio(in, out)
	if err != nil {
		t.Fatal(err)
	}
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { var b [1]byte; _, err := s.in.Read(b[:]); readDone <- err }()
	go func() { _, err := s.out.Write(make([]byte, 4<<20)); writeDone <- err }()
	time.Sleep(20 * time.Millisecond)
	s.close()
	for _, done := range []chan error{readDone, writeDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked pipe I/O succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("owned pipe Close did not interrupt I/O")
		}
	}
}

func TestMCPStdioDisconnectWatch(t *testing.T) {
	for _, closeInput := range []bool{true, false} {
		in, clientWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		defer clientWrite.Close()
		clientRead, out, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer clientRead.Close()
		defer out.Close()
		s, err := openMCPStdio(in, out)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stop := s.watchDisconnect(cancel)
		if closeInput {
			clientWrite.Close()
		} else {
			clientRead.Close()
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("pipe disconnect was not observed")
		}
		stop()
		s.close()
		cancel()
	}
}
