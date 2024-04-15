package auth

import "errors"

var (
	ErrBadDatabase = errors.New("auth: bad_database")
	ErrUnknown     = errors.New("auth: unknown")
)

var (
	ErrEmailNotFound   = errors.New("auth: email_not_found")
	ErrMobileNotFound  = errors.New("auth: mobile_not_found")
	ErrUserNotFound    = errors.New("auth: user_not_found")
	ErrProfileNotFound = errors.New("auth: profile_not_found")
	ErrPermNotFound    = errors.New("auth: perm_not_found")

	ErrPasswdNotMatched = errors.New("auth: passwd_not_matched")

	ErrOTPNotMatched  = errors.New("auth: otp_not_matched")
	ErrCodeNotMatched = errors.New("auth: code_not_matched")

	ErrInvalidToken = errors.New("auth: invalid_token")
)
