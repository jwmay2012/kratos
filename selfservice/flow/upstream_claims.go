// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"encoding/json"
)

type upstreamClaimsKey struct{}

type UpstreamClaims struct {
	Method   string          `json:"method"`
	Provider string          `json:"provider"`
	Claims   json.RawMessage `json:"claims"`
}

// WithUpstreamClaims snapshots verified strategy claims for this request's hooks, not flow persistence.
func WithUpstreamClaims(ctx context.Context, method, provider string, claims any) (context.Context, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, upstreamClaimsKey{}, &UpstreamClaims{Method: method, Provider: provider, Claims: payload}), nil
}

func UpstreamClaimsFromContext(ctx context.Context) *UpstreamClaims {
	claims, _ := ctx.Value(upstreamClaimsKey{}).(*UpstreamClaims)
	return claims
}
