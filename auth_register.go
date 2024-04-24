package auth

import "context"

// Register sign up with email or mobile
func (a *Auth) Register(ctx context.Context, status UserStatus, email, mobile, passwd, firstName, lastName string) (User, error) {
	return a.CreateUser(ctx, status, email, mobile, passwd, firstName, lastName)
}
