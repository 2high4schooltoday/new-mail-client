package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"despatch/internal/models"
)

func TestConsumePasswordResetTokenSingleUseUnderRace(t *testing.T) {
	st := newV2ScopedStore(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, "race-reset@example.com", "hash", "user", models.UserActive)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	tokenHash := "race-token-hash"
	if _, err := st.CreatePasswordResetToken(ctx, u.ID, tokenHash, time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatalf("create reset token: %v", err)
	}

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	var mu sync.Mutex
	successes := 0
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, consumeErr := st.ConsumePasswordResetToken(ctx, tokenHash)
			if consumeErr == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly one successful token consumption, got %d", successes)
	}
}
