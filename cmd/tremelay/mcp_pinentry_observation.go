package main

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

// Temporary, test-selected observations contain only fixed enums and booleans.
// Production passes nil. No helper text, passphrase metadata, errors, callbacks,
// or writers are retained here, and only the synchronous owner writes fields.
type pinentryObservation struct {
	phase          pinentryPhase
	outcome        pinentryOutcome
	classification pinentryContextState
	afterWatch     pinentryContextState
	reap           pinentryReap
	killAttempted  bool
	restore        pinentryRestore
}

type pinentryPhase uint8

const (
	pinentryPhaseUnset pinentryPhase = iota
	pinentryPhaseSetup
	pinentryPhaseGreeting
	pinentryPhaseConfigure
	pinentryPhaseGetPIN
	pinentryPhaseBye
	pinentryPhaseReap
)

type pinentryOutcome uint8

const (
	pinentryOutcomeUnset pinentryOutcome = iota
	pinentryOutcomeOK
	pinentryOutcomeEOF
	pinentryOutcomeReadError
	pinentryOutcomeWriteError
	pinentryOutcomeMalformed
	pinentryOutcomeLimit
	pinentryOutcomeERR99
	pinentryOutcomeERR198
	pinentryOutcomeERR62
	pinentryOutcomeERR277
	pinentryOutcomeERROther
)

type pinentryContextState uint8

const (
	pinentryContextUnset pinentryContextState = iota
	pinentryContextActive
	pinentryContextCancelled
	pinentryContextDeadline
	pinentryContextOther
)

type pinentryReap uint8

const (
	pinentryReapUnset pinentryReap = iota
	pinentryReapOK
	pinentryReapExit1
	pinentryReapExitOther
	pinentryReapSIGINT
	pinentryReapSIGTERM
	pinentryReapSIGKILL
	pinentryReapSignalOther
	pinentryReapOther
)

type pinentryRestore uint8

const (
	pinentryRestoreUnset pinentryRestore = iota
	pinentryRestoreOK
	pinentryRestoreFailed
)

func (o *pinentryObservation) begin(phase pinentryPhase) {
	if o != nil {
		o.phase, o.outcome = phase, pinentryOutcomeUnset
	}
}

func (o *pinentryObservation) result(outcome pinentryOutcome) {
	if o != nil {
		o.outcome = outcome
	}
}

func observePinentryContext(err error) pinentryContextState {
	switch {
	case err == nil:
		return pinentryContextActive
	case errors.Is(err, context.DeadlineExceeded):
		return pinentryContextDeadline
	case errors.Is(err, context.Canceled):
		return pinentryContextCancelled
	default:
		return pinentryContextOther
	}
}

func observePinentryReap(err error) pinentryReap {
	if err == nil {
		return pinentryReapOK
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ProcessState != nil {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				switch status.Signal() {
				case syscall.SIGINT:
					return pinentryReapSIGINT
				case syscall.SIGTERM:
					return pinentryReapSIGTERM
				case syscall.SIGKILL:
					return pinentryReapSIGKILL
				default:
					return pinentryReapSignalOther
				}
			}
			if status.Exited() {
				if status.ExitStatus() == 1 {
					return pinentryReapExit1
				}
				return pinentryReapExitOther
			}
		}
	}
	return pinentryReapOther
}
