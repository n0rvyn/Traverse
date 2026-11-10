package issuance

import (
	"errors"
	"github.com/go-acme/lego/v5/acme"
	"strings"
)

type authorizationFailure struct{ reason, problem string }

func (e *authorizationFailure) Error() string { return e.reason }
func authError(reason string) error           { return &authorizationFailure{reason: reason} }

func safeCAProblem(value string) string {
	name, ok := strings.CutPrefix(value, "urn:ietf:params:acme:error:")
	if !ok {
		return ""
	}
	switch name {
	case "connection", "dns", "tls", "unauthorized", "malformed", "incorrectResponse", "rejectedIdentifier", "badNonce", "orderNotReady", "serverInternal", "rateLimited":
		return name
	}
	return ""
}

func problemFromError(err error) string {
	var problem *acme.ProblemDetails
	if errors.As(err, &problem) {
		return safeCAProblem(problem.Type)
	}
	var nonce *acme.NonceError
	if errors.As(err, &nonce) && nonce.ProblemDetails != nil {
		return safeCAProblem(nonce.Type)
	}
	return ""
}

func validationFailure(a acme.Authorization) error {
	result := &authorizationFailure{reason: "ca_validation_failed"}
	for _, challenge := range a.Challenges {
		if challenge.Type == "tls-alpn-01" && challenge.Error != nil {
			result.problem = safeCAProblem(challenge.Error.Type)
		}
	}
	return result
}

func authorizationResult(err error) Result {
	result := failed("authorization_failed")
	var failure *authorizationFailure
	if errors.As(err, &failure) {
		result.Reason = failure.reason
		result.CAProblem = failure.problem
	}
	return result
}
