package issuance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
)

func Run(ctx context.Context, input io.Reader, output io.Writer) int {
	request, err := DecodeRequest(input)
	result := Result{Version: 1, Status: "failed", Code: "invalid_request"}
	if ctx.Err() != nil {
		result.Code = "cancelled"
	} else if err == nil {
		if request.Operation == "describe" {
			core, _, close, e := newCore(ctx, request, "", nil)
			if e == nil {
				terms := core.GetDirectory().Meta.TermsOfService
				if validateTermsURI(terms) == nil {
					result = Result{Version: 1, Status: "terms", TermsURL: terms}
				} else {
					result.Code = "invalid_ca_terms"
				}
			} else {
				result.Code = "ca_unavailable"
			}
			close()
		} else if request.Operation == "renewal-info" {
			result = renewalInfo(ctx, request, time.Now())
		} else {
			result = issue(ctx, request)
		}
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return 1
	}
	if result.Status == "failed" {
		return 1
	}
	if result.Code != "" {
		return 2
	}
	return 0
}

func failed(code string) Result { return Result{Version: 1, Status: "failed", Code: code} }

func issue(ctx context.Context, request Request) Result {
	if !request.TermsAgreed {
		return failed("consent_required")
	}
	store, err := OpenStore(request.StateDirectory, request.Directory)
	if err != nil {
		return failed("storage_unavailable")
	}
	defer store.Close()
	accountKey, err := store.AccountKey()
	if err != nil {
		return failed("account_key_unavailable")
	}
	saved, err := store.loadAccount(accountKey)
	if err != nil {
		return failed("account_state_invalid")
	}
	core, observer, close, err := newCore(ctx, request, saved.KID, accountKey)
	if err != nil {
		return failed("ca_unavailable")
	}
	defer close()
	metadata := core.GetDirectory().Meta
	if metadata.TermsOfService != request.TermsURL || validateTermsURI(metadata.TermsOfService) != nil {
		return failed("ca_terms_changed")
	}
	if metadata.ExternalAccountRequired {
		return failed("external_account_required")
	}
	if saved.KID == "" {
		account, e := core.Accounts.New(ctx, acme.Account{OnlyReturnExisting: true})
		if e != nil {
			var problem *acme.ProblemDetails
			if !errors.As(e, &problem) || problem.Type != acme.AccountDoesNotExistErrorType {
				return failed("account_lookup_failed")
			}
			account, e = core.Accounts.New(ctx, acme.Account{TermsOfServiceAgreed: true})
			if e != nil {
				return failed("account_registration_failed")
			}
		}
		if account.Status != acme.StatusValid || validateHTTPS(account.Location) != nil {
			return failed("account_identity_invalid")
		}
		saved.KID = account.Location
	} else {
		account, e := core.Accounts.Get(ctx, saved.KID)
		if e != nil || account.Status != acme.StatusValid {
			return failed("account_unavailable")
		}
	}
	fingerprint, err := keyFingerprint(accountKey)
	if err != nil {
		return failed("account_key_invalid")
	}
	saved = accountState{Version: 1, Directory: request.Directory, KID: saved.KID, KeyFingerprint: fingerprint, TermsURL: request.TermsURL}
	if err = store.saveJSON("account.json", saved); err != nil {
		return failed("account_state_uncertain")
	}
	pending, leafKey, err := store.pending(request.Domain)
	if err != nil {
		return failed("order_state_unavailable")
	}
	var order acme.ExtendedOrder
	if pending.OrderURL != "" {
		order, err = core.Orders.Get(ctx, pending.OrderURL)
		if err != nil {
			return failed("order_resume_failed")
		}
		if order.Status == acme.StatusInvalid || order.Status == acme.StatusExpired {
			pending.OrderURL = ""
		}
	}
	if pending.OrderURL == "" {
		var options *api.OrderOptions
		if core.GetDirectory().RenewalInfo != "" {
			if bundle, e := store.read("bundle.pem"); e == nil {
				if certificates, e := readCertificates(bundle); e == nil && len(certificates) > 0 && len(certificates[0].AuthorityKeyId) > 0 {
					if id, e := api.MakeARICertID(certificates[0]); e == nil {
						options = &api.OrderOptions{ReplacesCertID: id}
					}
				}
			} else if !errors.Is(e, fs.ErrNotExist) {
				return failed("managed_material_invalid")
			}
		}
		order, err = core.Orders.New(ctx, []string{request.Domain}, options)
		if err != nil {
			return failed("order_creation_failed")
		}
		if validateHTTPS(order.Location) != nil {
			return failed("order_identity_invalid")
		}
		pending.OrderURL = order.Location
		if err = store.saveJSON("pending.json", pending); err != nil {
			return failed("order_state_uncertain")
		}
	}
	if !orderMatches(order.Order, request.Domain) {
		return failed("order_identity_invalid")
	}
	if order.Status == acme.StatusPending {
		if len(order.Authorizations) == 0 {
			return failed("authorization_missing")
		}
		for _, uri := range order.Authorizations {
			authorization, e := core.Authorizations.Get(ctx, uri)
			if e != nil {
				return failed("authorization_unavailable")
			}
			if e = solveAuthorization(ctx, core, observer, request, order.Order, uri, authorization); e != nil {
				return authorizationResult(e)
			}
		}
		order, err = core.Orders.Get(ctx, pending.OrderURL)
		if err != nil {
			return failed("order_unavailable")
		}
	}
	order, err = awaitOrder(ctx, core, observer, pending.OrderURL, pending.OrderURL, request.Domain, order, true)
	if err != nil {
		return failed("order_not_ready")
	}
	if order.Status == acme.StatusReady {
		if validateHTTPS(order.Finalize) != nil {
			return failed("order_identity_invalid")
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{request.Domain}}, leafKey)
		if e != nil {
			return failed("csr_failed")
		}
		finalizeURI := order.Finalize
		order, err = core.Orders.UpdateForCSR(ctx, finalizeURI, csr)
		if err != nil {
			return failed("finalization_failed")
		}
		order, err = awaitOrder(ctx, core, observer, pending.OrderURL, finalizeURI, request.Domain, order, false)
		if err != nil {
			return failed("issuance_failed")
		}
	}
	if order.Status != acme.StatusValid || validateHTTPS(order.Certificate) != nil {
		return failed("certificate_unavailable")
	}
	certificate, err := core.Certificates.Get(ctx, order.Certificate, true)
	if err != nil {
		return failed("certificate_download_failed")
	}
	roots, err := readRoots(request.CertificateTrustFile)
	if err != nil {
		return failed("certificate_trust_unavailable")
	}
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	publication, err := store.Publish(certificate.Cert, []byte(pending.Key), request.Domain, roots, time.Now())
	if err != nil {
		if publication.Committed {
			return Result{Version: 1, Status: "published_durability_uncertain", Code: "storage_sync", Publication: &publication}
		}
		return failed("certificate_rejected")
	}
	pending.Completed = true
	result := Result{Version: 1, Status: "issued", Publication: &publication}
	if err = store.saveJSON("pending.json", pending); err != nil {
		result.Code = "recovery_state_uncertain"
	}
	return result
}

func orderMatches(order acme.Order, domain string) bool {
	if len(order.Identifiers) != 1 || order.Identifiers[0].Type != "dns" {
		return false
	}
	value, err := canonicalDNS(order.Identifiers[0].Value)
	return err == nil && value == domain
}

func authorizationMatches(a acme.Authorization, domain string) bool {
	value, err := canonicalDNS(a.Identifier.Value)
	return err == nil && value == domain && a.Identifier.Type == "dns" && !a.Wildcard
}

func leaseExpiry(order acme.Order, a acme.Authorization, now time.Time) (time.Time, error) {
	expires, err := time.Parse(time.RFC3339, order.Expires)
	if err != nil {
		return time.Time{}, authError("order_expiry_missing")
	}
	if !a.Expires.IsZero() && a.Expires.Before(expires) {
		expires = a.Expires
	}
	if !expires.After(now) {
		return time.Time{}, authError("authorization_expired")
	}
	return expires, nil
}

func solveAuthorization(ctx context.Context, core *api.Core, observer *operationTransport, request Request, order acme.Order, uri string, a acme.Authorization) error {
	if !authorizationMatches(a, request.Domain) {
		return authError("identity_mismatch")
	}
	if a.Status == acme.StatusValid {
		if a.Expires.IsZero() || !a.Expires.After(time.Now()) {
			return authError("authorization_expiry_invalid")
		}
		return nil
	}
	if a.Status != acme.StatusPending {
		return authError("authorization_terminal")
	}
	expires, err := leaseExpiry(order, a, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	var challenge *acme.Challenge
	for _, candidate := range a.Challenges {
		if candidate.Type == "tls-alpn-01" {
			if challenge != nil {
				return authError("challenge_ambiguous")
			}
			copy := candidate
			challenge = &copy
		}
	}
	if challenge == nil || validateHTTPS(challenge.URL) != nil || len(challenge.Token) < 22 {
		return authError("challenge_missing")
	}
	for _, c := range challenge.Token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return authError("challenge_token_invalid")
		}
	}
	keyAuthorization, err := core.GetKeyAuthorization(challenge.Token)
	if err != nil {
		return authError("challenge_key_authorization_failed")
	}
	lease, err := presentChallenge(ctx, request.ChallengeSocket, request.Domain, keyAuthorization, expires)
	if err != nil {
		return err
	}
	defer lease.Close()
	if challenge.Status == acme.StatusPending {
		if _, err = core.Challenges.New(ctx, challenge.URL); err != nil {
			return &authorizationFailure{reason: "challenge_trigger_failed", problem: problemFromError(err)}
		}
	} else if challenge.Status != acme.StatusProcessing && challenge.Status != acme.StatusValid {
		return authError("challenge_terminal")
	}
	source := challenge.URL
	for {
		if err = observer.wait(ctx, source); err != nil {
			return err
		}
		a, err = core.Authorizations.Get(ctx, uri)
		if err != nil {
			return &authorizationFailure{reason: "authorization_observation_failed", problem: problemFromError(err)}
		}
		if !authorizationMatches(a, request.Domain) {
			return authError("identity_changed")
		}
		if a.Status == acme.StatusValid {
			if a.Expires.IsZero() || !a.Expires.After(time.Now()) {
				return authError("authorization_expiry_invalid")
			}
			return nil
		}
		if a.Status != acme.StatusPending {
			return validationFailure(a)
		}
		source = uri
	}
}

func awaitOrder(ctx context.Context, core *api.Core, observer *operationTransport, uri, source, domain string, order acme.ExtendedOrder, allowReady bool) (acme.ExtendedOrder, error) {
	for {
		if !orderMatches(order.Order, domain) {
			return order, errors.New("Order identity changed")
		}
		if order.Status == acme.StatusValid || (allowReady && order.Status == acme.StatusReady) {
			return order, nil
		}
		if order.Status != acme.StatusPending && order.Status != acme.StatusProcessing {
			return order, errors.New("Order is terminal")
		}
		if order.Expires != "" {
			expires, err := time.Parse(time.RFC3339, order.Expires)
			if err != nil || !expires.After(time.Now()) {
				return order, errors.New("Order expiry invalid")
			}
		} else if order.Status == acme.StatusPending {
			return order, authError("order_expiry_missing")
		}
		if err := observer.wait(ctx, source); err != nil {
			return order, err
		}
		var err error
		order, err = core.Orders.Get(ctx, uri)
		if err != nil {
			return order, errors.New("Cannot observe order")
		}
		source = uri
	}
}

func readCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("Managed PEM invalid")
		}
		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("Managed certificate invalid")
			}
			certificates = append(certificates, certificate)
		} else if block.Type != "PRIVATE KEY" {
			return nil, errors.New("Unexpected managed PEM block")
		}
		data = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("Managed certificate missing")
	}
	return certificates, nil
}
