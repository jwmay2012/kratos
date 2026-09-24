// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestOIDCConfigValidationDoesNotLeakSecrets(t *testing.T) {
	const secret = "fixture-client-secret-must-not-be-logged"
	mode := os.Getenv("KRATOS_CONFIG_LOG_TEST")
	if mode == "" {
		for _, scenario := range []string{"startup", "reload"} {
			t.Run(scenario, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOIDCConfigValidationDoesNotLeakSecrets$")
				command.Env = append(os.Environ(), "KRATOS_CONFIG_LOG_TEST="+scenario)
				output, err := command.CombinedOutput()
				require.NoError(t, err, "%s", output)
				require.NotContains(t, string(output), secret)
				require.Contains(t, string(output), "selfservice/methods/oidc/config/providers/0/scope")
				if scenario == "reload" {
					require.Contains(t, string(output), "The changed configuration is invalid")
				}
			})
		}
		return
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	file := filepath.Join(t.TempDir(), "config.json")
	identitySchema := `{"$id":"https://example.invalid/schema.json","type":"object","properties":{"traits":{"type":"object","properties":{"email":{"type":"string"}}}}}`
	provider := map[string]any{"id": "test", "provider": "generic", "client_id": "fixture-client", "client_secret": secret, "issuer_url": "https://idp.example.invalid", "mapper_url": "base64://e30=", "scope": []string{"openid"}, "label": "Before"}
	settings := map[string]any{
		"dsn":         "memory",
		"identity":    map[string]any{"default_schema_id": "default", "schemas": []any{map[string]any{"id": "default", "url": "base64://" + base64.StdEncoding.EncodeToString([]byte(identitySchema))}}},
		"selfservice": map[string]any{"default_browser_return_url": "https://example.invalid/", "methods": map[string]any{"oidc": map[string]any{"enabled": true, "config": map[string]any{"providers": []any{provider}}}}},
	}
	write := func() {
		data, err := json.Marshal(settings)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(file+".new", data, 0o600))
		require.NoError(t, os.Rename(file+".new", file))
	}
	if mode == "startup" {
		provider["scope"] = "invalid-type"
	}
	write()
	logger := logrusx.New("config-test", "test")
	hook := test.NewLocal(logger.Logger)
	conf, err := config.New(ctx, logger, io.Discard, &contextx.Default{}, configx.WithConfigFiles(file), configx.DisableEnvLoading())
	if mode == "startup" {
		require.Error(t, err)
		fmt.Fprintln(os.Stdout, err)
		return
	}
	require.NoError(t, err)
	provider["scope"] = "invalid-type"
	provider["label"] = "Rejected"
	write()
	require.Eventually(t, func() bool {
		for _, entry := range hook.AllEntries() {
			if strings.Contains(entry.Message, "The changed configuration is invalid") {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	var retained struct{ Providers []struct{ Label string } }
	require.NoError(t, json.Unmarshal(conf.SelfServiceStrategy(ctx, "oidc").Config, &retained))
	require.Equal(t, "Before", retained.Providers[0].Label)
}
