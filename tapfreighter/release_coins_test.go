package tapfreighter

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type mockCoinReleaser struct {
	ctxErr      error
	hasDeadline bool
	deadline    time.Time
	outpoints   []wire.OutPoint
}

func (m *mockCoinReleaser) ReleaseCoins(ctx context.Context,
	ops ...wire.OutPoint) error {

	m.ctxErr = ctx.Err()
	m.deadline, m.hasDeadline = ctx.Deadline()
	m.outpoints = ops

	return ctx.Err()
}

// TestReleaseCoinsDetached makes sure coins are released even if the caller
// context is already canceled (taproot-assets#2206) and that the release is
// bounded.
func TestReleaseCoinsDetached(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ops := []wire.OutPoint{{Index: 1}, {Index: 2}}
	m := &mockCoinReleaser{}
	start := time.Now()
	releaseCoinsDetached(ctx, m, ops)

	require.NoError(t, m.ctxErr)
	require.Equal(t, ops, m.outpoints)
	require.True(t, m.hasDeadline)
	require.LessOrEqual(
		t, m.deadline.Sub(start), coinReleaseTimeout+time.Second,
	)
}
