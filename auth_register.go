package auth

import "context"

// Register sign up with email
func (a *Auth) Register(ctx context.Context, email, passwd, firstName, lastName string) (User, error) {
	return a.createLoginWithEmail(ctx, email, passwd, firstName, lastName)
}

// RegisterMobile sign up with mobile
func (a *Auth) RegisterMobile(ctx context.Context, mobile, passwd, firstName, lastName string) (User, error) {
	return a.createLoginWithMobile(ctx, mobile, passwd, firstName, lastName)
}
