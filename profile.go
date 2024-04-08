package auth

import (
	"time"

	"github.com/yaitoo/sqle/shardid"
)

type Profile struct {
	UserID    shardid.ID `json:"userID,omitempty"`
	Data      string     `json:"data"`
	CreatedAt time.Time  `json:"createdAt,omitempty"`
	UpdatedAt time.Time  `json:"updatedAt,omitempty"`
}

type ProfileData struct {
	Email  string `json:"email,omitempty"`
	Mobile string `json:"mobile,omitempty"`
	TKey   string `json:"tkey,omitempty"`
}
