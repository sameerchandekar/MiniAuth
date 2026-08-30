package handler

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

const loginHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MiniAuth - Sign In</title>
    <style>
        :root {
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.75);
            --card-border: rgba(255, 255, 255, 0.12);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --error-bg: rgba(239, 68, 68, 0.15);
            --error-border: rgba(239, 68, 68, 0.3);
            --error-text: #fca5a5;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body {
            background: var(--bg-gradient);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-main);
            padding: 1.5rem;
        }

        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(16px);
            border-radius: 1.25rem;
            padding: 2.5rem;
            max-width: 440px;
            width: 100%;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            animation: fadeIn 0.4s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .brand-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .brand-logo {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 56px;
            height: 56px;
            border-radius: 1rem;
            background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
            box-shadow: 0 10px 20px -5px rgba(99, 102, 241, 0.5);
            margin-bottom: 1rem;
        }

        .brand-title { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.025em; }
        .brand-subtitle { color: var(--text-muted); font-size: 0.95rem; margin-top: 0.35rem; }

        .alert-error {
            background: var(--error-bg);
            border: 1px solid var(--error-border);
            color: var(--error-text);
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.88rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-label {
            display: block;
            font-size: 0.88rem;
            font-weight: 500;
            margin-bottom: 0.45rem;
            color: #cbd5e1;
        }

        .form-input {
            width: 100%;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            padding: 0.75rem 1rem;
            border-radius: 0.6rem;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-input:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
        }

        .submit-btn {
            width: 100%;
            background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
            color: white;
            border: none;
            padding: 0.85rem;
            border-radius: 0.6rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.4);
            margin-top: 0.5rem;
        }

        .submit-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 15px 20px -3px rgba(79, 70, 229, 0.5);
        }

        .demo-box {
            margin-top: 1.75rem;
            padding-top: 1.25rem;
            border-top: 1px solid var(--card-border);
            text-align: center;
            font-size: 0.82rem;
            color: var(--text-muted);
        }

        .demo-box code {
            background: rgba(15, 23, 42, 0.8);
            padding: 0.2rem 0.45rem;
            border-radius: 0.35rem;
            color: #a5b4fc;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="brand-header">
            <div class="brand-logo">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
            </div>
            <h1 class="brand-title">Sign in to MiniAuth</h1>
            <p class="brand-subtitle">Enter your credentials to continue authorization</p>
        </div>

        {{if .Error}}
        <div class="alert-error">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>{{.Error}}</span>
        </div>
        {{end}}

        <form action="/login" method="POST">
            <input type="hidden" name="return_to" value="{{.ReturnTo}}">
            
            <div class="form-group">
                <label class="form-label" for="user_id">User ID or Email</label>
                <input class="form-input" type="text" id="user_id" name="user_id" placeholder="e.g. user-001 or admin" value="{{.UserID}}" required autofocus>
            </div>

            <div class="form-group">
                <label class="form-label" for="password">Password</label>
                <input class="form-input" type="password" id="password" name="password" placeholder="••••••••" required>
            </div>

            <button type="submit" class="submit-btn">Sign In & Authorize</button>
        </form>

        <div class="demo-box">
            <p>Demo credentials: User ID: <code>user-001</code> | Password: <code>password</code></p>
        </div>
    </div>
</body>
</html>`

// LoginPageData holds parameters passed to the login template.
type LoginPageData struct {
	ReturnTo string
	UserID   string
	Error    string
}

// LoginHandler handles user authentication, session cookies, and login page presentation.
type LoginHandler struct {
	authService service.AuthService
	loginTmpl   *template.Template
}

// NewLoginHandler creates a new LoginHandler.
func NewLoginHandler(authService service.AuthService) *LoginHandler {
	tmpl, _ := template.New("login").Parse(loginHTMLTemplate)
	return &LoginHandler{
		authService: authService,
		loginTmpl:   tmpl,
	}
}

// LoginPage handles GET /login.
func (h *LoginHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	// 1. Check if user already has a valid auth_session cookie
	if cookie, err := r.Cookie("auth_session"); err == nil && cookie.Value != "" {
		if sess, err := h.authService.ValidateSession(r.Context(), cookie.Value); err == nil && sess != nil {
			// Already logged in -> Redirect directly to return_to
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
	}

	data := LoginPageData{
		ReturnTo: returnTo,
		UserID:   r.URL.Query().Get("user_id"),
		Error:    r.URL.Query().Get("error"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.loginTmpl.Execute(w, data)
}

// Login handles POST /login (form submission or JSON).
func (h *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	var userID, password, returnTo string

	contentType := r.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	if isJSON {
		var req struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
			ReturnTo string `json:"return_to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
			return
		}
		userID = req.UserID
		password = req.Password
		returnTo = req.ReturnTo
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}
		userID = r.FormValue("user_id")
		password = r.FormValue("password")
		returnTo = r.FormValue("return_to")
	}

	if returnTo == "" {
		returnTo = "/"
	}

	// Authenticate credentials
	user, err := h.authService.Authenticate(r.Context(), userID, password)
	if err != nil {
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_credentials",
				"error_description": "Invalid user ID or password",
			})
			return
		}

		// Re-render / redirect to login page with error message
		redirectURL := "/login?error=" + url.QueryEscape("Invalid user ID or password") + "&return_to=" + url.QueryEscape(returnTo) + "&user_id=" + url.QueryEscape(userID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	// Create user session in Redis/Memory
	session, err := h.authService.CreateSession(r.Context(), user, 24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to create session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set HttpOnly auth_session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":       "success",
			"user_id":      user.ID,
			"session_id":   session.SessionID,
			"redirect_url": returnTo,
		})
		return
	}

	// HTTP 303 See Other redirect back to original authorization URL
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// Logout handles GET /logout and POST /logout.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("auth_session"); err == nil && cookie.Value != "" {
		_ = h.authService.RevokeSession(r.Context(), cookie.Value)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}
