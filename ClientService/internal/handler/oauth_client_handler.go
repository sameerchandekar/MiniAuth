package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/service"
)

// Embedded HTML templates
const indexHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MiniAuth Client App</title>
    <style>
        :root {
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.7);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            min-height: 100vh;
            background: var(--bg-gradient);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 24px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(16px);
        }

        .logo-icon {
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
            border-radius: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.5);
        }

        h1 {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }

        p {
            color: var(--text-muted);
            font-size: 1rem;
            line-height: 1.6;
            margin-bottom: 36px;
        }

        .btn-login {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            width: 100%;
            padding: 16px 24px;
            background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
            color: white;
            font-size: 1.05rem;
            font-weight: 600;
            text-decoration: none;
            border-radius: 14px;
            border: none;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 10px 20px -5px rgba(79, 70, 229, 0.4);
        }

        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 30px -5px rgba(79, 70, 229, 0.6);
            background: linear-gradient(135deg, #4338ca 0%, #4f46e5 100%);
        }

        .features {
            margin-top: 36px;
            padding-top: 24px;
            border-top: 1px solid var(--card-border);
            display: flex;
            justify-content: space-around;
            font-size: 0.82rem;
            color: var(--text-muted);
        }

        .feature-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <h1>MiniAuth Demo Client</h1>
        <p>Experience seamless OAuth 2.0 PKCE & OIDC authorization with our centralized identity provider.</p>
        
        <a href="/login" class="btn-login">
            <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/>
            </svg>
            Login with mini auth
        </a>

        <div class="features">
            <div class="feature-item">🔒 PKCE (S256)</div>
            <div class="feature-item">⚡ Redis State</div>
            <div class="feature-item">🛡️ RS256 JWT</div>
        </div>
    </div>
</body>
</html>`

const callbackHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Callback - MiniAuth Client</title>
    <style>
        :root {
            --primary: #4f46e5;
            --success: #10b981;
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.75);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --code-bg: #0f172a;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            min-height: 100vh;
            background: var(--bg-gradient);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 30px 20px;
        }

        .container {
            width: 100%;
            max-width: 700px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 36px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(16px);
        }

        .header {
            text-align: center;
            margin-bottom: 24px;
        }

        .success-icon {
            width: 48px;
            height: 48px;
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 12px;
        }

        .welcome-card {
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.2) 0%, rgba(168, 85, 247, 0.2) 100%);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 24px;
            text-align: center;
        }

        .welcome-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: #ffffff;
        }

        .welcome-sub {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }

        h1 {
            font-size: 1.6rem;
            font-weight: 700;
        }

        .token-grid {
            display: flex;
            flex-direction: column;
            gap: 16px;
            margin-bottom: 28px;
        }

        .token-item {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 14px 16px;
        }

        .token-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 600;
        }

        .token-val {
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.88rem;
            color: #38bdf8;
            word-break: break-all;
        }

        .raw-json-box {
            background: var(--code-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 24px;
            overflow-x: auto;
        }

        pre {
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.82rem;
            color: #a5f3fc;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .btn-home {
            display: inline-block;
            width: 100%;
            text-align: center;
            padding: 14px 20px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            text-decoration: none;
            font-weight: 600;
            border-radius: 12px;
            transition: all 0.2s ease;
        }

        .btn-home:hover {
            background: rgba(255, 255, 255, 0.15);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="success-icon">
                <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
                </svg>
            </div>
            <h1>Authentication Successful!</h1>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 4px;">Tokens received from MiniAuth Authorization Server</p>
        </div>

        {{ if .UserName }}
        <div class="welcome-card">
            <div class="welcome-title">Welcome, {{ .UserName }}! 👋</div>
            <div class="welcome-sub">Authenticated User ID: <strong style="color: #38bdf8;">{{ .UserID }}</strong>{{ if and .UserEmail (ne .UserName .UserEmail) }} &bull; <span>{{ .UserEmail }}</span>{{ end }}</div>
        </div>
        {{ else if .UserEmail }}
        <div class="welcome-card">
            <div class="welcome-title">Welcome, {{ .UserEmail }}! 👋</div>
            <div class="welcome-sub">Authenticated User ID: <strong style="color: #38bdf8;">{{ .UserID }}</strong></div>
        </div>
        {{ else if .UserID }}
        <div class="welcome-card">
            <div class="welcome-title">Welcome! 👋</div>
            <div class="welcome-sub">Authenticated User ID: <strong style="color: #38bdf8;">{{ .UserID }}</strong></div>
        </div>
        {{ end }}

        <div class="token-grid">
            {{ if .IDToken }}
            <div class="token-item">
                <div class="token-label">ID Token (OIDC Identity)</div>
                <div class="token-val" style="color: #fb923c;">{{ .IDToken }}</div>
            </div>
            {{ end }}

            <div class="token-item">
                <div class="token-label">Access Token (JWT)</div>
                <div class="token-val">{{ .AccessToken }}</div>
            </div>

            <div class="token-item">
                <div class="token-label">Refresh Token</div>
                <div class="token-val">{{ if .RefreshToken }}{{ .RefreshToken }}{{ else }}None{{ end }}</div>
            </div>

            <div style="display: flex; gap: 12px;">
                <div class="token-item" style="flex: 1;">
                    <div class="token-label">Token Type</div>
                    <div class="token-val" style="color: #4ade80;">{{ .TokenType }}</div>
                </div>
                <div class="token-item" style="flex: 1;">
                    <div class="token-label">Expires In</div>
                    <div class="token-val" style="color: #facc15;">{{ .ExpiresIn }} seconds</div>
                </div>
            </div>

            {{ if .Scope }}
            <div class="token-item">
                <div class="token-label">Granted Scope</div>
                <div class="token-val" style="color: #c084fc;">{{ .Scope }}</div>
            </div>
            {{ end }}
        </div>

        <div class="token-label" style="margin-bottom: 8px;">Raw JSON Response</div>
        <div class="raw-json-box">
            <pre>{{ .RawJSON }}</pre>
        </div>

        <a href="/" class="btn-home">&larr; Back to Client Home</a>
    </div>
</body>
</html>`

// CallbackPageData holds data rendered into the callback.html template.
type CallbackPageData struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	IDToken      string
	Scope        string
	UserName     string
	UserEmail    string
	UserID       string
	RawJSON      string
}

// OAuthClientHandler handles frontend and OAuth 2.0 client endpoints for ClientService.
type OAuthClientHandler struct {
	clientService *service.OAuthClientService
	indexTmpl     *template.Template
	callbackTmpl  *template.Template
}

// NewOAuthClientHandler creates a new OAuthClientHandler.
func NewOAuthClientHandler(clientService *service.OAuthClientService) *OAuthClientHandler {
	idxTmpl, _ := template.New("index").Parse(indexHTMLTemplate)
	cbTmpl, _ := template.New("callback").Parse(callbackHTMLTemplate)

	return &OAuthClientHandler{
		clientService: clientService,
		indexTmpl:     idxTmpl,
		callbackTmpl:  cbTmpl,
	}
}

// Index serves the main landing page with the "Login with mini auth" button.
func (h *OAuthClientHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.indexTmpl.Execute(w, nil)
}

// Login initiates the PKCE Authorization Code flow by redirecting to AuthorizationServer.
func (h *OAuthClientHandler) Login(w http.ResponseWriter, r *http.Request) {
	authURL, _, err := h.clientService.BuildAuthorizeURL(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate authorization URL: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles GET /oauth/callback from AuthorizationServer.
func (h *OAuthClientHandler) Callback(w http.ResponseWriter, r *http.Request) {
	// Handle authorization server error query params
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Authorization Error: %s (%s)", errParam, errDesc), http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing 'code' query parameter in callback", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing 'state' query parameter in callback", http.StatusBadRequest)
		return
	}

	// Verify state from Redis, delete it, and exchange code for tokens
	tokenRes, err := h.clientService.ExchangeCodeForToken(r.Context(), code, state)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusBadRequest)
		return
	}

	// If client requests JSON format directly
	if r.Header.Get("Accept") == "application/json" || r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenRes)
		return
	}

	// Extract Scope and User Identity from ID Token & Access Token
	rawJSONBytes, _ := json.MarshalIndent(tokenRes, "", "  ")
	scope := extractJWTScope(tokenRes.AccessToken)
	userName, userEmail, userID := extractIDTokenClaims(tokenRes.IDToken)

	if userID == "" {
		userID = extractJWTSubject(tokenRes.AccessToken)
	}
	if userName == "" {
		if userEmail != "" {
			userName = userEmail
		} else if userID != "" && !isUUIDString(userID) {
			userName = userID
		} else {
			userName = "User"
		}
	}

	data := CallbackPageData{
		AccessToken:  tokenRes.AccessToken,
		TokenType:    tokenRes.TokenType,
		ExpiresIn:    tokenRes.ExpiresIn,
		RefreshToken: tokenRes.RefreshToken,
		IDToken:      tokenRes.IDToken,
		Scope:        scope,
		UserName:     userName,
		UserEmail:    userEmail,
		UserID:       userID,
		RawJSON:      string(rawJSONBytes),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.callbackTmpl.Execute(w, data)
}

func extractJWTScope(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(payloadBytes, &claims)
	return claims.Scope
}

func extractJWTSubject(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return ""
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(payloadBytes, &claims)
	return claims.Sub
}

func extractIDTokenClaims(idToken string) (name, email, sub string) {
	if idToken == "" {
		return "", "", ""
	}
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", "", ""
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", ""
	}
	var claims struct {
		Name              string `json:"name"`
		Email             string `json:"email"`
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", "", ""
	}

	name = claims.Name
	email = claims.Email
	sub = claims.Sub

	// Prioritize human Name -> Email -> PreferredUsername (avoid raw UUID as display name)
	if isUUIDString(name) || name == "" {
		if email != "" {
			name = email
		} else if claims.PreferredUsername != "" && !isUUIDString(claims.PreferredUsername) {
			name = claims.PreferredUsername
		} else if sub != "" && !isUUIDString(sub) {
			name = sub
		}
	}

	return name, email, sub
}

func isUUIDString(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}
