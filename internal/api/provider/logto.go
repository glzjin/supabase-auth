package provider

import (
	"context"
	"fmt"
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
	oidc *oidc.Provider
}

func NewLogtoProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		oidc.ScopeOpenID,
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	issuerURL := ext.URL
	if issuerURL == "" {
		return nil, fmt.Errorf("missing Logto issuer URL")
	}

	oidcProvider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	return &LogtoProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       oauthScopes,
			RedirectURL:  ext.RedirectURI,
		},
		oidc: oidcProvider,
	}, nil
}

func (p *LogtoProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p *LogtoProvider) GetUserData(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	verifier := p.oidc.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})

	idToken, err := verifier.Verify(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	_, data, err := parseLogtoIDToken(idToken)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (p *LogtoProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	return p.GetUserData(ctx, token)
}
