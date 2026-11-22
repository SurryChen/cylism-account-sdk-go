// Package account provides typed clients for Cylism Account's public, application,
// user, and administrator APIs, plus OIDC login and HTTP authorization helpers.
// Application secrets belong on the server. Cookie clients must be isolated per
// signed-in person; application credentials never grant administrator access.
package account
