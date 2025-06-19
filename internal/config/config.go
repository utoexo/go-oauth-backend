package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	DBUrl             string
	PrivateKey        *rsa.PrivateKey
	PublicKey         *rsa.PublicKey
	OAuthClientID     string
	OAuthClientSecret string
	OAuthRedirectURL  string
	Port              string
	Issuer            string
	Audience          string
}

func LoadRSAPrivateKey(path string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read private key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("failed to decode PEM block containing private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse PKCS#1 private key: %v", err)
		}
	case "PRIVATE KEY":
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse PKCS#8 private key: %v", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatalf("not an RSA private key")
		}
	default:
		log.Fatalf("unsupported key type %q", block.Type)
	}
	return key
}

func LoadRSAPublicKey(path string) *rsa.PublicKey {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read public key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatalf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("not an RSA public key")
	}
	return key
}

func LoadConfig() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // default port
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "https://ishare.example.com" // professional default
	}

	aud := os.Getenv("JWT_AUDIENCE")
	if aud == "" {
		aud = "https://ishare.example.com/api" // professional default
	}

	return &Config{
		DBUrl:             os.Getenv("DATABASE_URL"),
		PrivateKey:        LoadRSAPrivateKey("../../private_key.pem"),
		PublicKey:         LoadRSAPublicKey("../../public_key.pem"),
		OAuthClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		OAuthClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		OAuthRedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
		Port:              port,
		Issuer:            issuer,
		Audience:          aud,
	}
}
