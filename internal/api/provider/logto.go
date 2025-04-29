package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	IssuerLogto = "https://mydas.wetolink.com/oidc"
)

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type LogtoIDTokenClaims struct {
	jwt.RegisteredClaims

	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type LogtoUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Phone         string `json:"phone"`
	PhoneVerified bool   `json:"phone_verified"`
}

type OpenIDConfiguration struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func parseLogtoIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var claims LogtoIDTokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, nil, err
	}

	var data UserProvidedData

	if claims.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    claims.Email,
			Verified: claims.EmailVerified,
			Primary:  true,
		})
	}

	data.Metadata = &Claims{
		Issuer:  token.Issuer,
		Subject: token.Subject,
		Name:    claims.Name,
		Picture: claims.Picture,

		// To be deprecated
		AvatarURL:  claims.Picture,
		FullName:   claims.Name,
		ProviderId: token.Subject,
	}

	return token, &data, nil
}

type LogtoProvider struct {
	*oauth2.Config
	oidc   *oidc.Provider
	config *OpenIDConfiguration
}

func NewLogtoProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	issuerURL := ext.URL
	if issuerURL == "" {
		return nil, fmt.Errorf("missing Logto issuer URL")
	}

	// 获取 OpenID 配置
	configURL := issuerURL + "/.well-known/openid-configuration"
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get OpenID configuration: status=%d body=%s", resp.StatusCode, string(body))
	}

	var config OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OpenID configuration: %w", err)
	}

	oauthScopes := []string{
		oidc.ScopeOpenID,
		"profile",
		"email",
		"phone",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	oidcProvider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}

	return &LogtoProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthorizationEndpoint,
				TokenURL: config.TokenEndpoint,
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		oidc:   oidcProvider,
		config: &config,
	}, nil
}

func (p *LogtoProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	ctx := context.Background()
	token, err := p.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// 验证 ID token
	verifier := p.oidc.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})

	_, err = verifier.Verify(ctx, token.Extra("id_token").(string))
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	return token, nil
}

func (p *LogtoProvider) GetUserData(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	// 使用 access token 获取用户信息
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status=%d body=%s", resp.StatusCode, string(body))
	}

	var userInfo LogtoUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	var data UserProvidedData

	// 如果存在手机号，优先使用手机号作为主要联系方式
	if userInfo.Phone != "" {
		data.Emails = append(data.Emails, Email{
			Email:    userInfo.Phone,
			Verified: userInfo.PhoneVerified,
			Primary:  true,
		})
	} else if userInfo.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    userInfo.Email,
			Verified: userInfo.EmailVerified,
			Primary:  true,
		})
	}

	data.Metadata = &Claims{
		Issuer:  p.config.Issuer,
		Subject: userInfo.Sub,
		Name:    userInfo.Name,
		Picture: userInfo.Picture,

		// To be deprecated
		AvatarURL:  userInfo.Picture,
		FullName:   userInfo.Name,
		ProviderId: userInfo.Sub,
	}

	return &data, nil
}

func (p *LogtoProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	return p.GetUserData(ctx, token)
}
