package models

import (
	"time"

	"github.com/google/uuid"
)

// Client represents an OAuth2 client (for registration, authorization, and token exchange)
// swagger:model OAuthClient
//
//	Example: {
//	  "id": "123e4567-e89b-12d3-a456-426614174000",
//	  "client_name": "My App",
//	  "client_secret": "s3cr3t",
//	  "redirect_uris": ["http://localhost:8081/callback"],
//	  "grant_types": ["authorization_code"],
//	  "response_types": ["code"],
//	  "token_endpoint_auth_method": "client_secret_basic",
//	  "scope": "tasks",
//	  "created_at": "2025-06-18T10:00:00Z",
//	  "updated_at": "2025-06-18T10:00:00Z"
//	}
type Client struct {
	ID                      uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	ClientName              string    `json:"client_name"`
	ClientSecret            string    `json:"client_secret"`
	RedirectURIs            []string  `gorm:"type:jsonb;serializer:json" json:"redirect_uris"`
	GrantTypes              []string  `gorm:"type:jsonb;serializer:json" json:"grant_types"`
	ResponseTypes           []string  `gorm:"type:jsonb;serializer:json" json:"response_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	Scope                   string    `json:"scope"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}
