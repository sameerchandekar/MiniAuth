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
            --accent: #38bdf8;
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

        .container {
            width: 100%;
            max-width: 520px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(16px);
            text-align: center;
        }

        .badge {
            display: inline-block;
            background: rgba(79, 70, 229, 0.2);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            margin-bottom: 20px;
        }

        h1 {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 12px;
            background: linear-gradient(to right, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        p.subtitle {
            color: var(--text-muted);
            font-size: 0.95rem;
            line-height: 1.5;
            margin-bottom: 32px;
        }

        .btn-login {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            width: 100%;
            padding: 16px 24px;
            background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%);
            color: #ffffff;
            font-size: 1.05rem;
            font-weight: 600;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
            box-shadow: 0 10px 25px -5px rgba(79, 70, 229, 0.4);
        }

        .btn-login:hover {
            background: linear-gradient(135deg, var(--primary-hover) 0%, var(--primary) 100%);
            transform: translateY(-2px);
            box-shadow: 0 15px 30px -5px rgba(79, 70, 229, 0.6);
        }

        .btn-login svg {
            width: 22px;
            height: 22px;
        }

        .features {
            margin-top: 36px;
            padding-top: 28px;
            border-top: 1px solid var(--card-border);
            text-align: left;
        }

        .feature-item {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text-muted);
            font-size: 0.88rem;
            margin-bottom: 12px;
        }

        .feature-item:last-child {
            margin-bottom: 0;
        }

        .feature-icon {
            color: #10b981;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">OAuth 2.0 &amp; PKCE Client</div>
        <h1>Client Application</h1>
        <p class="subtitle">Securely sign in and authenticate against MiniAuth Authorization Server using Authorization Code Flow + PKCE (RFC 7636).</p>

        <a href="/login" class="btn-login" id="loginButton">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
            Login with mini auth
        </a>

        <div class="features">
            <div class="feature-item">
                <span class="feature-icon">&#10003;</span>
                <span>PKCE S256 Code Challenge Protection</span>
            </div>
            <div class="feature-item">
                <span class="feature-icon">&#10003;</span>
                <span>Automatic /oauth/callback Token Exchange</span>
            </div>
            <div class="feature-item">
                <span class="feature-icon">&#10003;</span>
                <span>Refresh Token &amp; Access Token Retrieval</span>
            </div>
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
            max-width: 680px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 36px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(16px);
        }

        .header {
            text-align: center;
            margin-bottom: 28px;
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

        <div class="token-grid">
            <div class="token-item">
                <div class="token-label">Access Token</div>
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
	Scope        string
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
	idxTmpl := template.Must(template.New("index").Parse(indexHTMLTemplate))
	cbTmpl := template.Must(template.New("callback").Parse(callbackHTMLTemplate))

	return &OAuthClientHandler{
		clientService: clientService,
		indexTmpl:     idxTmpl,
		callbackTmpl:  cbTmpl,
	}
}

// Index renders the landing page with the 'Login with mini auth' button.
func (h *OAuthClientHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.indexTmpl.Execute(w, nil)
}

// Login triggers the OAuth 2.0 authorization flow.
// It generates PKCE credentials, stores state in Redis, and redirects the user-agent to AuthorizationServer /authorize.
func (h *OAuthClientHandler) Login(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := h.clientService.BuildAuthorizeURL(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to initiate authorization: %v", err), http.StatusInternalServerError)
		return
	}

	// Support JSON response if client specifically requested application/json
	if r.Header.Get("Accept") == "application/json" || r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorize_url": authURL,
			"state":         state,
		})
		return
	}

	// Browser redirect (HTTP 302 Found) to AuthorizationServer
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles GET /oauth/callback from AuthorizationServer redirect.
// It verifies the state ID from Redis, deletes it, and exchanges the authorization code for tokens.
func (h *OAuthClientHandler) Callback(w http.ResponseWriter, r *http.Request) {
	// Check for error parameter from authorization server
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OAuth error from authorization server: %s (%s)", errParam, errDesc), http.StatusBadRequest)
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

	// Render beautiful HTML callback page
	rawJSONBytes, _ := json.MarshalIndent(tokenRes, "", "  ")
	scope := extractJWTScope(tokenRes.AccessToken)

	data := CallbackPageData{
		AccessToken:  tokenRes.AccessToken,
		TokenType:    tokenRes.TokenType,
		ExpiresIn:    tokenRes.ExpiresIn,
		RefreshToken: tokenRes.RefreshToken,
		Scope:        scope,
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
