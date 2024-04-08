package auth

// LoginOption options for login
type LoginOption struct {
	// CreateIfNotExists create account if user doesn't exists
	CreateIfNotExists bool
	// UserIP user's ip address
	UserIP string
	// UserAgent user's device info
	UserAgent string

	// FirstName first name. only use when CreateIfNotExists is true
	FirstName string
	// LastName last name. only use when CreateIfNotExists is true
	LastName string
}
