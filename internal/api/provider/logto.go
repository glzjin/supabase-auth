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
	"github.com/sirupsen/logrus"
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
	Sub                 string   `json:"sub"`
	Name                *string  `json:"name"`
	Picture             *string  `json:"picture"`
	UpdatedAt           int64    `json:"updated_at"`
	Username            *string  `json:"username"`
	CreatedAt           int64    `json:"created_at"`
	Email               *string  `json:"email"`
	EmailVerified       bool     `json:"email_verified"`
	PhoneNumber         string   `json:"phone_number"`
	PhoneNumberVerified bool     `json:"phone_number_verified"`
	Roles               []string `json:"roles"`
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
	oidc       *oidc.Provider
	config     *OpenIDConfiguration
	allowRoles []string
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
		"roles",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	oidcProvider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}

	// 解析允许的角色
	var allowRoles []string
	if ext.AllowRoles != "" {
		allowRoles = strings.Split(ext.AllowRoles, ",")
		for i, role := range allowRoles {
			allowRoles[i] = strings.TrimSpace(role)
		}
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
		oidc:       oidcProvider,
		config:     &config,
		allowRoles: allowRoles,
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

	logrus.WithFields(logrus.Fields{
		"endpoint": p.config.UserInfoEndpoint,
		"token":    token.AccessToken[:10] + "...", // 只显示token的前10个字符
	}).Info("Requesting user info from Logto")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logrus.WithFields(logrus.Fields{
		"status": resp.StatusCode,
		"body":   string(body),
	}).Info("Received response from Logto user info endpoint")

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status=%d body=%s", resp.StatusCode, string(body))
	}

	var userInfo LogtoUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"sub":                   userInfo.Sub,
		"email":                 userInfo.Email,
		"email_verified":        userInfo.EmailVerified,
		"phone_number":          userInfo.PhoneNumber,
		"phone_number_verified": userInfo.PhoneNumberVerified,
		"name":                  userInfo.Name,
		"roles":                 userInfo.Roles,
	}).Info("Successfully parsed user info from Logto")

	// 验证用户角色
	if len(p.allowRoles) > 0 {
		hasAllowedRole := false
		for _, role := range userInfo.Roles {
			for _, allowedRole := range p.allowRoles {
				if role == allowedRole {
					hasAllowedRole = true
					break
				}
			}
			if hasAllowedRole {
				break
			}
		}

		if !hasAllowedRole {
			logrus.WithFields(logrus.Fields{
				"user_roles":    userInfo.Roles,
				"allowed_roles": p.allowRoles,
			}).Error("User does not have any of the allowed roles")
			return nil, fmt.Errorf("user does not have any of the allowed roles")
		}
	}

	var data UserProvidedData

	// 如果存在手机号，优先使用手机号作为主要联系方式
	if userInfo.PhoneNumber != "" {
		data.Emails = append(data.Emails, Email{
			Email:    userInfo.PhoneNumber,
			Verified: userInfo.PhoneNumberVerified,
			Primary:  true,
		})
		logrus.WithField("phone", userInfo.PhoneNumber).Info("Using phone as primary contact")
	} else if userInfo.Email != nil && *userInfo.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    *userInfo.Email,
			Verified: userInfo.EmailVerified,
			Primary:  true,
		})
		logrus.WithField("email", *userInfo.Email).Info("Using email as primary contact")
	}

	var name string
	if userInfo.Name != nil {
		name = *userInfo.Name
	}

	var picture string
	if userInfo.Picture != nil {
		picture = *userInfo.Picture
	}

	data.Metadata = &Claims{
		Issuer:  p.config.Issuer,
		Subject: userInfo.Sub,
		Name:    name,
		Picture: picture,

		// To be deprecated
		AvatarURL:  picture,
		FullName:   name,
		ProviderId: userInfo.Sub,
	}

	return &data, nil
}

func (p *LogtoProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	return p.GetUserData(ctx, token)
}
