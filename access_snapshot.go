package account

import (
	"context"
	"net/url"
	"time"
)

func (c *Client) applicationEntitlements(ctx context.Context, subject string) (AccessEntitlements, error) {
	if !validAccessText(subject, 128) {
		return AccessEntitlements{}, ErrInvalidResponse
	}
	value, err := c.cache.get(ctx, cacheKey{"permissions", subject}, func(ctx context.Context) (any, time.Time, error) {
		until := time.Now().Add(c.cache.config.TTL)
		out, err := c.fetchEntitlements(ctx, subject)
		if !c.cache.config.Disabled && until.Before(out.ValidUntil) {
			out.ValidUntil = until
		}
		return out, out.ValidUntil, err
	})
	if err != nil {
		return AccessEntitlements{}, err
	}
	return cloneEntitlements(value.(AccessEntitlements)), nil
}

// ApplicationEntitlementsOnline always loads a fresh snapshot from Account.
func (c *Client) ApplicationEntitlementsOnline(ctx context.Context, subject string) (AccessEntitlements, error) {
	c.cache.forget(cacheKey{"permissions", subject})
	defer c.cache.forget(cacheKey{"permissions", subject})
	return c.fetchEntitlements(ctx, subject)
}

func (c *Client) fetchEntitlements(ctx context.Context, subject string) (AccessEntitlements, error) {
	var out AccessEntitlements
	err := c.request(ctx, "GET", "/api/app/v1/access/users/"+escapeSegment(subject), url.Values(nil), nil, &out, "application", []int{200})
	if err != nil {
		return AccessEntitlements{}, err
	}
	if out.Subject != subject || out.ApplicationID == "" || out.Version < 0 || out.Roles == nil || out.Permissions == nil || !out.ValidUntil.After(time.Now()) || (out.Status != "active" && out.Status != "disabled" && out.Status != "removed") {
		return AccessEntitlements{}, ErrInvalidResponse
	}
	return out, nil
}

func cloneEntitlements(out AccessEntitlements) AccessEntitlements {
	if out.ApplicationName != nil {
		name := *out.ApplicationName
		out.ApplicationName = &name
	}
	out.Roles = append([]string{}, out.Roles...)
	out.Permissions = append([]EffectivePermission{}, out.Permissions...)
	for i := range out.Permissions {
		out.Permissions[i].Sources = append([]string{}, out.Permissions[i].Sources...)
	}
	return out
}

func (c *Client) verifyPasswordSession(ctx context.Context, input PasswordTokenInput) (PasswordSession, error) {
	if input.Token == "" {
		return PasswordSession{}, ErrUnauthenticated
	}
	// Do not retain caller-owned pointers in a background loader.
	if input.ClientContext != nil {
		clientContext := *input.ClientContext
		if clientContext.IP != nil {
			ip := *clientContext.IP
			clientContext.IP = &ip
		}
		if clientContext.UserAgent != nil {
			agent := *clientContext.UserAgent
			clientContext.UserAgent = &agent
		}
		input.ClientContext = &clientContext
	}
	value, err := c.cache.get(ctx, tokenCacheKey("password", input.Token), func(ctx context.Context) (any, time.Time, error) {
		out, err := c.fetchPasswordSession(ctx, input)
		return out, out.ExpiresAt, err
	})
	if err != nil {
		return PasswordSession{}, err
	}
	out := value.(PasswordSession)
	if out.Email != nil {
		email := *out.Email
		out.Email = &email
	}
	return out, nil
}

// VerifyPasswordSessionOnline checks an opaque password session without a cache.
func (c *Client) VerifyPasswordSessionOnline(ctx context.Context, input PasswordTokenInput) (PasswordSession, error) {
	c.cache.forget(tokenCacheKey("password", input.Token))
	defer c.cache.forget(tokenCacheKey("password", input.Token))
	return c.fetchPasswordSession(ctx, input)
}

func (c *Client) fetchPasswordSession(ctx context.Context, input PasswordTokenInput) (PasswordSession, error) {
	var out PasswordSession
	err := c.request(ctx, "POST", "/api/app/v1/password/verify", url.Values(nil), input, &out, "application", []int{200})
	if err != nil {
		return PasswordSession{}, err
	}
	if out.Subject == "" || !out.ExpiresAt.After(time.Now()) {
		return PasswordSession{}, ErrInvalidResponse
	}
	return out, nil
}
