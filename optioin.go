package auth

import (
	"hash"

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
