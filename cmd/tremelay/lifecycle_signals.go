package main

import (
	"os"
	"os/signal"
	"syscall"
)

func lifecyclePipeErrors() func() {
	// Notify prevents default SIGPIPE termination for stdout/stderr writes.
	// Signals need not be consumed: the runtime returns EPIPE to the writer,
	// and Notify drops a duplicate rather than blocking if this channel is full.
	pipe := make(chan os.Signal, 1)
	signal.Notify(pipe, syscall.SIGPIPE)
	return func() { signal.Stop(pipe) }
}
