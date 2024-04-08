package auth

import (
	"hash"
	"time"

	"github.com/yaitoo/sqle/shardid"
)

type Option func(a *Auth)

// WithPrefix add prefix for auth tables
func WithPrefix(prefix string) Option {
	return func(a *Auth) {
		a.prefix = prefix
	}
}

// WithGenUser set custom shardid generator for user id
func WithGenUser(gen *shardid.Generator) Option {
	return func(a *Auth) {
		a.genUser = gen
	}
}

// WithGenLogin set custom shardid generator for login id
func WithGenLogin(gen *shardid.Generator) Option {
	return func(a *Auth) {
		a.genLoginLog = gen
	}
}

// WithGenAuditLog set custom shardid generator for audit log id
func WithGenAuditLog(gen *shardid.Generator) Option {
	return func(a *Auth) {
		a.genUser = gen
	}
}

// WithHash set custom hash
func WithHash(h func() hash.Hash) Option {
	return func(a *Auth) {
		a.hash = h
	}
}

// WithAES setup AES key
func WithAES(key string) Option {
	return func(a *Auth) {
		a.aesKey = getAESKey(key)
	}
}

// WithAccessTokenTTL  setup ttl for access token
func WithAccessTokenTTL(d time.Duration) Option {
	return func(a *Auth) {
		if d > 0 {
			a.accessTokenTTL = d
		}
	}
}

// WithRefreshTokenTTL setup ttl for refresh token
func WithRefreshTokenTTL(d time.Duration) Option {
	return func(a *Auth) {
		if d > 0 {
			a.refreshTokenTTL = d
		}
	}
}

// WithJWT setup jwt signature key
func WithJWT(signKey string) Option {
	return func(a *Auth) {
		a.jwtSignKey = getJWTKey(signKey)
	}
}
