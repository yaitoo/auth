package auth

import "errors"

var (
	ErrBadDatabase = errors.New("auth: bad_database")
	ErrBadCrypto   = errors.New("auth: bad_crypto")
)

var (
	ErrEmailNotFound = errors.New("auth: email_not_found")
	ErrUserNotFound  = errors.New("auth: user_not_found")
)
