package vault

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestVaultWriteRetriesBusy(t *testing.T) {
	var calls atomic.Int32
	err := vaultWriteRun(func() error {
		if calls.Add(1) < 3 {
			return errSQLiteBusy
		}
		return nil
	})
	if err != nil {
		t.Fatalf("vaultWriteRun: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("attempts %d", calls.Load())
	}
}

func TestVaultWriteBusyExhaustedReturnsErrIO(t *testing.T) {
	err := vaultWriteRun(func() error { return errSQLiteBusy })
	if !errors.Is(err, ErrIO) {
		t.Fatalf("got %v", err)
	}
}

func TestVaultWriteAuditFaultNotRetried(t *testing.T) {
	var calls atomic.Int32
	err := vaultWriteRun(func() error {
		calls.Add(1)
		return ErrAudit
	})
	if !errors.Is(err, ErrAudit) {
		t.Fatalf("got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("audit fault retried %d times", calls.Load())
	}
}

// TestSQLiteConcurrentWritersStress hammers every store write path from many
// connections at once. This is stricter than the reload and SSH interop flakes:
// a single ErrIO from write-lock starvation fails the test.
func TestSQLiteConcurrentWritersStress(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	vaultID := session.id
	session.Lock()

	const (
		connections = 20
		writesEach  = 30
	)
	var wg sync.WaitGroup
	errs := make(chan error, connections*writesEach)
	for range connections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := openDB(path)
			if err != nil {
				errs <- err
				return
			}
			defer db.Close()
			for range writesEach {
				errs <- appendDenial(db, vaultID)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteConcurrentSessionCommitsNoErrIO(t *testing.T) {
	env := grantedAttestEnv(t)
	control, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.Lock)

	const (
		workers     = 12
		commitsEach = 15
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers*commitsEach*2)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range commitsEach {
				if _, err := env.s.CreateAgent("w-" + randHex(t, 6)); err != nil && !errors.Is(err, ErrStale) {
					errs <- err
					return
				}
				if _, err := control.CreateAgent("c-" + randHex(t, 6)); err != nil && !errors.Is(err, ErrStale) {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if errors.Is(err, ErrIO) {
			t.Fatalf("write starvation: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
}
