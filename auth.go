package auth

import (
	"crypto/sha256"
	"embed"
	"hash"
	"log/slog"
	"strings"
	"time"

	"github.com/yaitoo/sqle"
	"github.com/yaitoo/sqle/migrate"
	"github.com/yaitoo/sqle/shardid"
)

var (
	//go:embed migration
	migration embed.FS

	defaultAccessTokenTTL  = 1 * time.Minute
	defaultRefreshTokenTTL = 1 * time.Hour
	defaultTOTPIssuer      = "Yaitoo"
	defaultTOPTAccountName = "Auth"
	defaultDHTEmail        = "auth:email"
	defaultDHTMobile       = "auth:mobile"
	defaultSignInCodeLen   = 6
	defaultSignInCodeTTL   = 60 * time.Second
)

var (
	noSession     Session
	noProfileData ProfileData
)

type Auth struct {
	db     *sqle.DB
	prefix string
	logger *slog.Logger

	hash func() hash.Hash

	aesKey []byte

	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	jwtSignKey      []byte

	totpIssuer      string
	totpAccountName string

	signInCodeLen int
	signInCodeTTL time.Duration

	dhtEmail  string
	dhtMobile string

	genUser     *shardid.Generator
	genLoginLog *shardid.Generator
	genAuditLog *shardid.Generator
}

// New create an auth provider with db and options
// skipcq: GO-R1005
func New(db *sqle.DB, options ...Option) *Auth {
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

	if a.accessTokenTTL <= 0 {
		a.accessTokenTTL = defaultAccessTokenTTL
	}

	if a.refreshTokenTTL <= 0 {
		a.refreshTokenTTL = defaultRefreshTokenTTL
	}

	if a.jwtSignKey == nil {
		a.jwtSignKey = getJWTKey("")
	}

	if a.totpIssuer == "" {
		a.totpIssuer = defaultTOTPIssuer
	}

	if a.totpAccountName == "" {
		a.totpAccountName = defaultTOPTAccountName
	}

	if a.dhtEmail == "" {
		a.dhtEmail = defaultDHTEmail
	}

	if a.dhtMobile == "" {
		a.dhtMobile = defaultDHTMobile
	}

	if a.signInCodeLen < 1 {
		a.signInCodeLen = defaultSignInCodeLen
	}

	if a.signInCodeTTL < 1 {
		a.signInCodeTTL = defaultSignInCodeTTL
	}

	return a
}

// CreateMigrator automatically migrate database schema for auth module
func (a *Auth) CreateMigrator(options ...migrate.Option) (*migrate.Migrator, error) {
	m := migrate.New(a.db)

	options = append(options, migrate.WithModule("auth"))
	err := m.Discover(migration, options...)
	if err != nil {
		return nil, err
	}

	var vers []migrate.Semver

	for _, v := range m.Versions {

		var migrations []migrate.Migration
		for _, m := range v.Migrations {
			m.Scripts = strings.ReplaceAll(m.Scripts, "<prefix>", a.prefix)
			migrations = append(migrations, m)
		}

		v.Migrations = migrations
		vers = append(vers, v)
	}

	m.Versions = vers

	return m, nil
}
