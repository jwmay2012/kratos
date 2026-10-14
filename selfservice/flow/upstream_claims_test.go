// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/selfservice/flow"
)

func TestUpstreamClaimsRequestContext(t *testing.T) {
	base := context.Background()
	claims := map[string]any{"sub": "verified-subject", "raw_claims": map[string]any{"team": "north"}}
	ctx, err := flow.WithUpstreamClaims(base, "oidc", "example", claims)
	require.NoError(t, err)
	claims["sub"] = "later-change"
	assert.Nil(t, flow.UpstreamClaimsFromContext(base))
	assert.Nil(t, flow.UpstreamClaimsFromContext(context.Background()))
	payload, err := json.Marshal(flow.UpstreamClaimsFromContext(context.WithoutCancel(ctx)))
	require.NoError(t, err)
	assert.JSONEq(t, `{"method":"oidc","provider":"example","claims":{"sub":"verified-subject","raw_claims":{"team":"north"}}}`, string(payload))
	_, err = flow.WithUpstreamClaims(base, "oidc", "example", make(chan int))
	require.Error(t, err)
}
