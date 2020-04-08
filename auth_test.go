package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserFromContext_Found(t *testing.T) {
	u := &User{AuthorizationValue: "lol"}

	ctx := context.Background()
	ctx = ContextWithUser(ctx, u)

	ctxUser, ok := UserFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, u, ctxUser)
}

func TestUserFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	ctxUser, ok := UserFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, ctxUser)
}
