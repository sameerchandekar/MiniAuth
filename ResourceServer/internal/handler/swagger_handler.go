package handler

import (
	"net/http"
)

const openAPISpec = `openapi: 3.0.3
info:
  title: MiniAuth Resource Server API
  description: |
    Protected Resource Server API for MiniAuth OAuth 2.0 Identity Platform.
    Enforces JWT access token verification via RS256 and fine-grained scope authorization.
    
    - **read / email scope**: Required for GET /api/v1/emails
    - **write scope**: Required for POST /api/v1/emails (denied if token only has read)
  version: 1.0.0
servers:
  - url: http://localhost:8082
    description: Local Resource Server

paths:
  /api/v1/emails:
    get:
      summary: List Protected Emails
      description: |
        Retrieves user emails.
        **Requires scope:** read or email.
      tags:
        - Emails
      security:
        - BearerAuth: []
      responses:
        '200':
          description: Emails successfully retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/EmailListResponse'
        '401':
          description: Missing or invalid JWT access token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Insufficient scope (requires 'read' or 'email')
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    post:
      summary: Send New Email
      description: |
        Sends a new email message.
        **Requires scope:** write.
        *Will be rejected with 403 Forbidden if access token only contains read scope.*
      tags:
        - Emails
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SendEmailRequest'
      responses:
        '201':
          description: Email sent successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SendEmailResponse'
        '401':
          description: Unauthorized - Invalid or missing token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '403':
          description: Forbidden - Insufficient scope (requires 'write')
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /api/v1/userinfo:
    get:
      summary: Get Token Identity & Claims
      description: Returns verified subject, client_id, and scopes contained in the access token.
      tags:
        - Identity
      security:
        - BearerAuth: []
      responses:
        '200':
          description: Token claims retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserInfoResponse'
        '401':
          description: Unauthorized

  /healthz:
    get:
      summary: Liveness Probe
      description: Returns service health status
      tags:
        - Health
      responses:
        '200':
          description: Service is healthy

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: Enter your MiniAuth RS256 JWT access token (obtained from POST /token)

  schemas:
    EmailMessage:
      type: object
      properties:
        id:
          type: string
          example: "msg-001"
        from:
          type: string
          example: "security@miniauth.com"
        to:
          type: string
          example: "user@example.com"
        subject:
          type: string
          example: "OAuth 2.0 Access Token Verified"
        snippet:
          type: string
          example: "Your RS256 JWT access token was successfully validated against MiniAuth JWKS."
        received_at:
          type: string
          format: date-time

    EmailListResponse:
      type: object
      properties:
        status:
          type: string
          example: "success"
        user_id:
          type: string
          example: "client-id-001"
        client_id:
          type: string
          example: "client-id-001"
        scope:
          type: string
          example: "openid profile email read"
        count:
          type: integer
          example: 2
        emails:
          type: array
          items:
            $ref: '#/components/schemas/EmailMessage'

    SendEmailRequest:
      type: object
      required:
        - to
        - subject
        - body
      properties:
        to:
          type: string
          example: "partner@example.com"
        subject:
          type: string
          example: "Project Collaboration Update"
        body:
          type: string
          example: "Hello team, here is the latest API integration summary."

    SendEmailResponse:
      type: object
      properties:
        status:
          type: string
          example: "sent"
        id:
          type: string
          example: "msg-new-20260830213000"
        from:
          type: string
          example: "client-id-001"
        to:
          type: string
          example: "partner@example.com"
        subject:
          type: string
          example: "Project Collaboration Update"
        sent_at:
          type: string
          format: date-time

    UserInfoResponse:
      type: object
      properties:
        sub:
          type: string
          example: "client-id-001"
        client_id:
          type: string
          example: "client-id-001"
        scope:
          type: string
          example: "openid profile email"
        iss:
          type: string
          example: "http://localhost:8080"
        aud:
          type: array
          items:
            type: string
          example: ["client-id-001"]
        exp:
          type: integer
          example: 1756654024

    ErrorResponse:
      type: object
      properties:
        error:
          type: string
          example: "insufficient_scope"
        error_description:
          type: string
          example: "Access denied: requires one of the following scopes [write, write:email]"
`

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MiniAuth Resource Server - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
    <style>
        body { margin: 0; padding: 0; background: #0f172a; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui { color: #f8fafc; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/swagger/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`

// SwaggerHandler serves the Swagger UI and the OpenAPI 3.0 YAML spec.
type SwaggerHandler struct{}

// NewSwaggerHandler creates a new SwaggerHandler.
func NewSwaggerHandler() *SwaggerHandler {
	return &SwaggerHandler{}
}

// UI renders the interactive Swagger UI web interface.
func (h *SwaggerHandler) UI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerUIHTML))
}

// Spec serves the OpenAPI YAML specification file.
func (h *SwaggerHandler) Spec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(openAPISpec))
}
