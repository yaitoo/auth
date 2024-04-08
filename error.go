package auth

import "errors"

var (
	ErrBadDatabase   = errors.New("auth: bad_database")
	ErrBadCrypto     = errors.New("auth: bad_crypto")
	ErrBadJWTSignKey = errors.New("auth: bad_jwt_signature_key")
)

var (
	ErrEmailNotFound    = errors.New("auth: email_not_found")
	ErrMobileNotFound   = errors.New("auth: mobile_not_found")
	ErrUserNotFound     = errors.New("auth: user_not_found")
	ErrPasswdNotMatched = errors.New("auth: passwd_not_matched")
)
