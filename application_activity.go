package account

import (
	"context"
	"net/url"
	"time"
)

// RenewApplicationSession records REAL user activity. Background verification
// never calls it. Successful renewals are coalesced for Account's RenewAfter;
// restart loses only this optimization, not the Account-owned login session.
func (c *Client) renewApplicationSession(ctx context.Context, in RenewApplicationSessionInput) (ApplicationSessionIdentity, error) {
	if len(in.Token) != 43 {
		return ApplicationSessionIdentity{}, ErrUnauthenticated
	}
	// A renewal receipt is not a five-minute authorization. Always establish
	// an independently bounded identity before reusing the reporting timestamp.
	verified, err := c.VerifyApplicationSession(ctx, VerifyApplicationSessionInput{Token: in.Token})
	if err != nil {
		return ApplicationSessionIdentity{}, err
	}
	// A separate, non-refreshing entry shares the bounded cache and single-flight
	// transport; background refresh explicitly skips activity entries.
	value, e := c.cache.get(ctx, tokenCacheKey("session-activity", in.Token), func(ctx context.Context) (any, time.Time, error) {
		var out ApplicationSessionIdentity
		if e := c.request(ctx, "POST", "/api/app/v1/sessions/renew", url.Values(nil), in, &out, "application", []int{200}); e != nil {
			return nil, time.Time{}, e
		}
		if !validApplicationIdentity(out) || out.RenewAfter == nil || !out.RenewAfter.After(time.Now()) || out.RenewAfter.After(time.Now().Add(5*time.Minute)) || out.CookieExpiresAt == nil || !out.CookieExpiresAt.After(time.Now()) || out.CookieExpiresAt.After(out.ExpiresAt) || (out.Token != nil && len(*out.Token) != 43) {
			return nil, time.Time{}, ErrInvalidResponse
		}
		return out, *out.RenewAfter, nil
	})
	if e != nil {
		return ApplicationSessionIdentity{}, e
	}
	receipt := cloneApplicationSession(value.(ApplicationSessionIdentity))
	if receipt.Subject != verified.Subject || receipt.SessionID != verified.SessionID || receipt.ApplicationID != verified.ApplicationID {
		return ApplicationSessionIdentity{}, ErrInvalidResponse
	}
	// A fresh receipt may reflect the extension just committed by Account. A
	// cached receipt must not replace newer identity or policy verification.
	if receipt.ValidUntil.Before(verified.ValidUntil) {
		verified.Token = receipt.Token
		verified.RenewAfter = receipt.RenewAfter
		if receipt.CookieExpiresAt != nil {
			deadline := *receipt.CookieExpiresAt
			if deadline.After(verified.ExpiresAt) {
				deadline = verified.ExpiresAt
			}
			verified.CookieExpiresAt = &deadline
		}
		return cloneApplicationSession(verified), nil
	}
	return receipt, nil
}
func validApplicationIdentity(out ApplicationSessionIdentity) bool {
	return out.Subject != "" && out.ApplicationID != "" && out.SessionID != "" && out.ValidUntil.After(time.Now()) && out.ExpiresAt.After(time.Now()) && !out.ValidUntil.After(out.ExpiresAt) && !out.ExpiresAt.After(out.AbsoluteExpiresAt)
}
