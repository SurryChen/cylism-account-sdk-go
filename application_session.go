package account

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// CompleteApplicationLogin performs standard OIDC state/PKCE/nonce/ID-token
// validation, then exchanges the live access token for an Account-owned session.
// Persist only the opaque Token in an application HttpOnly cookie. Neither OAuth
// token rotation nor a per-application login database is needed for this path.
func (o *OIDC) CompleteApplicationLogin(ctx context.Context, callback url.Values, tx LoginTransaction) (ApplicationSessionLogin, error) {
	var empty ApplicationSessionLogin
	if values, ok := callback["iss"]; ok && (len(values) != 1 || values[0] != o.client.base.String()) {
		return empty, errors.New("account: invalid callback issuer")
	}
	result, err := o.CompleteLogin(ctx, callback, tx)
	if err != nil {
		return empty, err
	}
	out, err := o.client.ExchangeApplicationSession(ctx, ExchangeApplicationSessionInput{AccessToken: result.Tokens.AccessToken})
	if err != nil {
		return empty, err
	}
	if len(out.Token) != 43 || out.Subject != result.Profile.Subject || out.ApplicationID == "" || out.SessionID == "" || !out.ExpiresAt.After(time.Now()) || out.ExpiresAt.After(out.AbsoluteExpiresAt) || out.ValidUntil.After(out.ExpiresAt) || !out.ValidUntil.After(time.Now()) {
		return empty, ErrInvalidResponse
	}
	return out, nil
}

func (c *Client) verifyApplicationSession(ctx context.Context, input VerifyApplicationSessionInput) (ApplicationSessionIdentity, error) {
	if len(input.Token) != 43 {
		return ApplicationSessionIdentity{}, ErrUnauthenticated
	}
	value, err := c.cache.get(ctx, tokenCacheKey("application-session", input.Token), func(ctx context.Context) (any, time.Time, error) {
		out, err := c.fetchApplicationSession(ctx, input)
		return out, out.ValidUntil, err
	})
	if err != nil {
		return ApplicationSessionIdentity{}, err
	}
	return cloneApplicationSession(value.(ApplicationSessionIdentity)), nil
}

// VerifyApplicationSessionOnline bypasses the default cache for sensitive work.
func (c *Client) VerifyApplicationSessionOnline(ctx context.Context, input VerifyApplicationSessionInput) (ApplicationSessionIdentity, error) {
	key := tokenCacheKey("application-session", input.Token)
	c.cache.forget(key)
	defer c.cache.forget(key)
	return c.fetchApplicationSession(ctx, input)
}
func (c *Client) fetchApplicationSession(ctx context.Context, input VerifyApplicationSessionInput) (ApplicationSessionIdentity, error) {
	var out ApplicationSessionIdentity
	if len(input.Token) != 43 {
		return out, ErrUnauthenticated
	}
	if err := c.request(ctx, "POST", "/api/app/v1/sessions/verify", url.Values(nil), input, &out, "application", []int{200}); err != nil {
		return out, err
	}
	if out.Subject == "" || out.ApplicationID == "" || out.SessionID == "" || !out.ValidUntil.After(time.Now()) || !out.ExpiresAt.After(time.Now()) || out.ValidUntil.After(out.ExpiresAt) || out.ExpiresAt.After(out.AbsoluteExpiresAt) {
		return ApplicationSessionIdentity{}, ErrInvalidResponse
	}
	return out, nil
}
func cloneApplicationSession(out ApplicationSessionIdentity) ApplicationSessionIdentity {
	if out.Email != nil {
		v := *out.Email
		out.Email = &v
	}
	if out.Name != nil {
		v := *out.Name
		out.Name = &v
	}
	return out
}
