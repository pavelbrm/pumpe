package gate

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type mockTorCreator struct {
	fnNew func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error)
}

func (c *mockTorCreator) new(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
	if c.fnNew == nil {
		return newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}), nil
	}

	return c.fnNew(ctx, dtout, cltout)
}
