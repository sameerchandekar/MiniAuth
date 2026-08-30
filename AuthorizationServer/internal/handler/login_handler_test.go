package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

func newTestLoginHandler() (*LoginHandler, service.AuthService, service.SessionStore) {
	sessionStore := service.NewMemorySessionStore()
	authService := service.NewAuthService(nil, sessionStore)
	h := NewLoginHandler(authService)
	return h, authService, sessionStore
}

func TestLoginHandler_LoginPage_Render(t *testing.T) {
	h, _, _ := newTestLoginHandler()

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=/authorize?client_id=my-client", nil)
	rec := httptest.NewRecorder()

	h.LoginPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Sign in to MiniAuth") {
		t.Errorf("expected login page title in HTML body")
	}
	if !strings.Contains(body, "/authorize?client_id=my-client") {
		t.Errorf("expected return_to parameter preserved in form")
	}
}

func TestLoginHandler_LoginPage_AlreadyLoggedInRedirect(t *testing.T) {
	h, authService, _ := newTestLoginHandler()

	// Pre-create session and cookie
	user := &service.UserInfo{ID: "user-001", Email: "user@example.com"}
	sess, _ := authService.CreateSession(context.Background(), user, 0)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=/authorize?client_id=123", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sess.SessionID})
	rec := httptest.NewRecorder()

	h.LoginPage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found redirect for already logged-in user, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/authorize?client_id=123" {
		t.Errorf("expected redirect location '/authorize?client_id=123', got '%s'", rec.Header().Get("Location"))
	}
}

func TestLoginHandler_Login_Success(t *testing.T) {
	h, _, _ := newTestLoginHandler()

	form := url.Values{}
	form.Set("user_id", "user-001")
	form.Set("password", "password")
	form.Set("return_to", "/authorize?client_id=my-client")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303 See Other, got %d", rec.Code)
	}

	if rec.Header().Get("Location") != "/authorize?client_id=my-client" {
		t.Errorf("expected redirect to '/authorize?client_id=my-client', got '%s'", rec.Header().Get("Location"))
	}

	// Verify auth_session cookie was set
	cookies := rec.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_session" {
			authCookie = c
			break
		}
	}
	if authCookie == nil || authCookie.Value == "" {
		t.Fatalf("expected auth_session cookie to be set")
	}
	if !authCookie.HttpOnly {
		t.Errorf("expected auth_session cookie to be HttpOnly")
	}
}

func TestLoginHandler_Login_InvalidCredentials(t *testing.T) {
	h, _, _ := newTestLoginHandler()

	form := url.Values{}
	form.Set("user_id", "user-001")
	form.Set("password", "wrong_password")
	form.Set("return_to", "/authorize?client_id=my-client")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303 See Other redirect on login error, got %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "/login?error=") {
		t.Errorf("expected redirect to login with error query param, got '%s'", location)
	}
}
