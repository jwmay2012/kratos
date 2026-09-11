// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/logrusx"
)

func TestHookErrorLogPreservesTraceContext(t *testing.T) {
	for _, withSpan := range []bool{false, true} {
		t.Run(map[bool]string{false: "without span", true: "with span"}[withSpan], func(t *testing.T) {
			var output bytes.Buffer
			logger := logrusx.New("kratos", "test", logrusx.ForceFormat("json"), logrusx.ForceLevel(logrus.ErrorLevel))
			logger.Logrus().SetOutput(&output)
			request := httptest.NewRequest("POST", "/fixture", nil)
			spanContext := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
			})
			if withSpan {
				request = request.WithContext(trace.ContextWithSpanContext(request.Context(), spanContext))
			}
			err := HandleHookError(nil, request, newTestFlow(request, TypeAPI), identity.Traits("not-json"),
				node.PasswordGroup, errors.New("fixture"), &x.BasicRegistry{L: logger}, &testCSRFTokenGenerator{})
			require.Error(t, err)
			var record map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			require.Equal(t, "could not update flow UI", record["msg"])
			if withSpan {
				fields := record["otel"].(map[string]any)
				require.Equal(t, spanContext.TraceID().String(), fields["trace_id"])
				require.Equal(t, spanContext.SpanID().String(), fields["span_id"])
			} else {
				require.NotContains(t, record, "otel")
			}
		})
	}
}
