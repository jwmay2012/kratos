#!/bin/sh
set -eu

# No Docker daemon or external database is needed for this build gate.
# The broader upstream suite remains a separate release acceptance step.
oidc_tests='Test(NativeIDTokenNonceCompatibility.*|MicrosoftNativeIDTokenVerification|GenericNativeIDTokenVerification|GoogleVerify|AppleVerify)$'
listed=$(go test -tags sqlite ./selfservice/strategy/oidc -list "$oidc_tests")
for name in TestNativeIDTokenNonceCompatibility TestNativeIDTokenNonceCompatibilityStillRequiresValidClaims \
    TestMicrosoftNativeIDTokenVerification TestGenericNativeIDTokenVerification TestGoogleVerify TestAppleVerify; do
    printf '%s\n' "$listed" | grep -Fxq "$name" || {
        printf 'Required fork regression is missing: %s\n' "$name" >&2
        exit 1
    }
done

go test -p 2 -parallel 1 -tags sqlite -count=1 ./selfservice/strategy/oidc -run "$oidc_tests" -timeout 5m
go test -p 2 -parallel 1 -tags sqlite -count=1 ./selfservice/flow ./selfservice/hook ./session -timeout 10m
