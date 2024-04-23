package auth

import (
	"time"

	"github.com/yaitoo/sqle/shardid"
)

// UserStatus user's status
type UserStatus int

const (
	// UserStatusWaiting waiting for verifying, can do anything within waiting period
	UserStatusWaiting UserStatus = 0
	// UserStatusActivated activated means can do anything
	UserStatusActivated UserStatus = 1
	// UserStatusSuspended suspended means only can view, can't write anymore
	UserStatusSuspended UserStatus = -1
	// UserStatusDeactivated deactivated means can do nothing
	UserStatusDeactivated UserStatus = -2
)

// User user info
type User struct {
	ID        shardid.ID `json:"id,omitempty"`
	Status    UserStatus `json:"status"`
	FirstName string     `json:"firstName,omitempty"`
	LastName  string     `json:"lastName,omitempty"`
	// Passwd the hash of user's password with salt
	Passwd string `json:"-"`
	Salt   string `json:"-"`

	Email  string `json:"email,omitempty"`
	Mobile string `json:"mobile,omitempty"`

	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}
