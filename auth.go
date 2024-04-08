package auth

import (
	"crypto/sha256"
	"embed"
	"hash"
	"log/slog"
	"strings"

	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/shardid"
)

var (
	//go:embed migration
	migration embed.FS
)

type Auth struct {
	db     *sqle.DB
	prefix string
	logger *slog.Logger

	hash func() hash.Hash

	aesKey []byte

	genUser     *shardid.Generator
	genLoginLog *shardid.Generator
	genAuditLog *shardid.Generator
}

func NewAuth(db *sqle.DB, options ...Option) *Auth {
	a := &Auth{
		db: db,
	}

	for _, o := range options {
		o(a)
	}

	if a.prefix != "" && !strings.HasSuffix(a.prefix, "_") {
		a.prefix = a.prefix + "_"
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}

	if a.hash == nil {
		a.hash = sha256.New
	}

	if a.genUser == nil {
		a.genUser = shardid.New()
	}

	if a.genLoginLog == nil {
		a.genLoginLog = shardid.New()
	}

	if a.genAuditLog == nil {
		a.genAuditLog = shardid.New()
	}

	return a
}
