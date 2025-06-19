package auth

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"crypto/rsa"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ishare/taskapi/internal/config"
	"github.com/ishare/taskapi/internal/models"
	"gorm.io/gorm"
)

type TokenRequest struct {
	Code string `json:"code"`
}

// TokenResponse represents the response from the token endpoint.
// swagger:model TokenResponse
//
//	Example: {
//	  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "token_type": "Bearer",
//	  "expires_in": 3600
//	}
type TokenResponse struct {
	AccessToken string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType   string `json:"token_type" example:"Bearer"`
	ExpiresIn   int    `json:"expires_in" example:"3600"`
}

// Add this struct for public client listing
type OAuthClientPublic struct {
	ID          string `json:"client_id" example:"demo-client"`
	RedirectURI string `json:"redirect_uri" example:"http://localhost:8081/callback"`
}

// --- OAuth 2.0 Client Registry ---

// ListClientsEndpoint godoc
// @Summary List available OAuth clients
// @Description Returns the list of registered OAuth clients (excluding secrets) for testing/demo purposes.
// @Tags OAuth2
// @Produce json
// @Success 200 {array} OAuthClientPublic
// @Router /clients [get]
func ListClientsEndpoint(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var clients []models.Client
		if err := db.Find(&clients).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clients"})
			return
		}
		var out []OAuthClientPublic
		for _, cl := range clients {
			redir := ""
			if len(cl.RedirectURIs) > 0 {
				redir = cl.RedirectURIs[0]
			}
			out = append(out, OAuthClientPublic{ID: cl.ID.String(), RedirectURI: redir})
		}
		c.JSON(200, out)
	}
}

// --- Authorization Code Store ---

type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Expiry      time.Time
	Used        bool
}

var (
	codeStore   = make(map[string]*AuthCode)
	codeStoreMu sync.Mutex
)

func generateAuthCode() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func storeAuthCode(code, clientID, redirectURI string, duration time.Duration) {
	codeStoreMu.Lock()
	defer codeStoreMu.Unlock()
	codeStore[code] = &AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Expiry:      time.Now().Add(duration),
		Used:        false,
	}
}

func validateAndUseAuthCode(code, clientID, redirectURI string) bool {
	codeStoreMu.Lock()
	defer codeStoreMu.Unlock()
	ac, ok := codeStore[code]
	if !ok || ac.Used || ac.ClientID != clientID || ac.RedirectURI != redirectURI || time.Now().After(ac.Expiry) {
		return false
	}
	ac.Used = true
	return true
}

// --- Enhanced OAuth 2.0 /token Endpoint ---
type TokenRequestForm struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
}

// KeyStore represents a store of signing keys
type KeyStore struct {
	Keys map[string]*rsa.PrivateKey
	mu   sync.RWMutex
}

var keyStore = &KeyStore{
	Keys: make(map[string]*rsa.PrivateKey),
}

// RegisterKey adds a new signing key to the store
func (ks *KeyStore) RegisterKey(kid string, key *rsa.PrivateKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.Keys[kid] = key
}

// GetKey retrieves a signing key by its ID
func (ks *KeyStore) GetKey(kid string) *rsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.Keys[kid]
}

// TokenEndpoint godoc
// @Summary OAuth2 Token Endpoint
// @Description Exchanges an authorization code for a JWT access token
// @Tags OAuth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant Type"
// @Param code formData string true "Authorization Code"
// @Param redirect_uri formData string true "Redirect URI"
// @Param client_id formData string true "Client ID"
// @Param client_secret formData string true "Client Secret"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /token [post]
func TokenEndpoint(cfg *config.Config, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TokenRequestForm
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
			return
		}
		var client models.Client
		if err := db.First(&client, "id = ?", req.ClientID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials or redirect_uri"})
			return
		}
		if client.ClientSecret != req.ClientSecret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials or redirect_uri"})
			return
		}
		uriMatch := false
		for _, uri := range client.RedirectURIs {
			if uri == req.RedirectURI {
				uriMatch = true
				break
			}
		}
		if !uriMatch {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials or redirect_uri"})
			return
		}
		if !validateAndUseAuthCode(req.Code, req.ClientID, req.RedirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid, expired, or already used code"})
			return
		}
		kid := fmt.Sprintf("key-%d", time.Now().UnixNano())
		claims := jwt.MapClaims{
			"iss":       cfg.Issuer,
			"sub":       req.ClientID,
			"aud":       cfg.Audience,
			"exp":       time.Now().Add(time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"jti":       fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(100000)),
			"client_id": req.ClientID,
			"scope":     client.Scope,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		token.Header["typ"] = "JWT"
		token.Header["x5u"] = fmt.Sprintf("%s/.well-known/jwks.json", cfg.Issuer)
		signed, err := token.SignedString(cfg.PrivateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign token"})
			return
		}
		c.JSON(http.StatusOK, TokenResponse{
			AccessToken: signed,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}
}

// --- OAuth 2.0 /authorize Endpoint ---

// AuthorizeEndpoint godoc
// @Summary OAuth2 Authorization Endpoint
// @Description Initiates the OAuth2 Authorization Code Flow. Redirects with code and state.
// @Tags OAuth2
// @Produce json
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param response_type query string true "Response Type (must be 'code')"
// @Param state query string true "CSRF State"
// @Success 302 {string} string "Redirects to client redirect_uri with code and state"
// @Failure 400 {object} map[string]string
// @Router /authorize [get]
func AuthorizeEndpoint(cfg *config.Config, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		responseType := c.Query("response_type")
		state := c.Query("state")
		if clientID == "" || redirectURI == "" || responseType == "" || state == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
			return
		}
		if responseType != "code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "response_type must be 'code'"})
			return
		}
		var client models.Client
		if err := db.First(&client, "id = ?", clientID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id"})
			return
		}
		uriMatch := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				uriMatch = true
				break
			}
		}
		if !uriMatch {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid redirect_uri"})
			return
		}
		code := generateAuthCode()
		storeAuthCode(code, clientID, redirectURI, 5*time.Minute)
		redir := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
		c.Redirect(http.StatusFound, redir)
	}
}

// JWKSResponse represents the JSON Web Key Set response
// swagger:model JWKSResponse
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ClientRegistrationRequest represents a request to register a new OAuth client
// swagger:model ClientRegistrationRequest
type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	GrantTypes              []string `json:"grant_types" binding:"required"`
	ResponseTypes           []string `json:"response_types" binding:"required"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" binding:"required"`
	Scope                   string   `json:"scope" binding:"required"`
}

// ClientRegistrationResponse represents the response from client registration
// swagger:model ClientRegistrationResponse
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// RegisterClientEndpoint godoc
// @Summary Register a new OAuth client
// @Description Register a new OAuth client following iSHARE specifications
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body ClientRegistrationRequest true "Client Registration Request"
// @Success 201 {object} ClientRegistrationResponse
// @Failure 400 {object} map[string]string
// @Router /register [post]
func RegisterClientEndpoint(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ClientRegistrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
			return
		}
		// Validate grant types
		validGrantTypes := map[string]bool{
			"authorization_code": true,
			"client_credentials": true,
		}
		for _, gt := range req.GrantTypes {
			if !validGrantTypes[gt] {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid grant type: " + gt})
				return
			}
		}
		// Validate redirect URIs
		for _, uri := range req.RedirectURIs {
			if _, err := url.Parse(uri); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid redirect URI: " + uri})
				return
			}
		}
		// Validate scope
		validScopes := map[string]bool{
			"tasks": true,
			"read":  true,
			"write": true,
		}
		scopes := strings.Split(req.Scope, " ")
		for _, scope := range scopes {
			if !validScopes[scope] {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scope: " + scope})
				return
			}
		}
		clientSecret := fmt.Sprintf("%x", rand.Int63())
		client := models.Client{
			ClientName:              req.ClientName,
			ClientSecret:            clientSecret,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              req.GrantTypes,
			ResponseTypes:           req.ResponseTypes,
			TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
			Scope:                   req.Scope,
		}
		if err := db.Create(&client).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register client"})
			return
		}
		c.JSON(http.StatusCreated, ClientRegistrationResponse{
			ClientID:                client.ID.String(),
			ClientSecret:            client.ClientSecret,
			ClientName:              client.ClientName,
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           client.ResponseTypes,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			Scope:                   client.Scope,
		})
	}
}
