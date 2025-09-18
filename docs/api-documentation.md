# API Documentation

## Base URL
```
http://localhost:3001/api
```

## Authentication
Most endpoints require authentication via JWT tokens in the Authorization header:
```
Authorization: Bearer <access_token>
```

## Error Response Format
```json
{
  "success": false,
  "message": "Error description",
  "errors": [
    {
      "field": "field_name",
      "message": "Field-specific error message"
    }
  ]
}
```

## Health Check Endpoints

### GET /health
Basic health check for the auth server.

**Response:**
```json
{
  "success": true,
  "message": "Auth Server is running",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "uptime": 123.456,
  "version": "1.0.0",
  "database": {
    "status": "connected",
    "name": "scalai_auth"
  }
}
```

### GET /health/detailed
Detailed health information including database statistics.

**Response:**
```json
{
  "success": true,
  "message": "Auth Server is healthy",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "uptime": 123.456,
  "version": "1.0.0",
  "environment": "development",
  "memory": {
    "used": 25.54,
    "total": 29.31,
    "external": 19.81
  },
  "system": {
    "platform": "darwin",
    "arch": "arm64",
    "nodeVersion": "v22.17.0"
  },
  "database": {
    "status": "connected",
    "name": "scalai_auth",
    "host": "cluster0.mongodb.net",
    "stats": {
      "users": {
        "total": 100,
        "active": 95
      },
      "refreshTokens": {
        "total": 250,
        "active": 180
      }
    }
  }
}
```

## Authentication Endpoints

### POST /auth/register
Register a new user account.

**Rate Limit:** 3 attempts per hour per IP

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Validation Rules:**
- `email`: Valid email format, required
- `password`: Minimum 8 characters, must contain uppercase, lowercase, number, and special character
- `firstName`: 2-50 characters, required
- `lastName`: 2-50 characters, required

**Response (201):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "isActive": true,
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-01-01T00:00:00.000Z"
    },
    "accessToken": "jwt_access_token",
    "refreshToken": "jwt_refresh_token"
  }
}
```

### POST /auth/login
Authenticate user and receive tokens.

**Rate Limit:** 5 attempts per 15 minutes per IP

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "isActive": true,
      "lastLogin": "2025-01-01T00:00:00.000Z"
    },
    "accessToken": "jwt_access_token",
    "refreshToken": "jwt_refresh_token",
    "securityInfo": {
      "riskLevel": "low",
      "newDevice": false,
      "flags": []
    }
  }
}
```

**Security Info Fields:**
- `riskLevel`: "low", "medium", or "high"
- `newDevice`: Boolean indicating if login is from new IP/device
- `flags`: Array of security flags like "multiple_ips", "rapid_location_change"

### POST /auth/refresh-token
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "jwt_refresh_token"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "new_jwt_access_token",
    "refreshToken": "new_jwt_refresh_token"
  }
}
```

**Security Features:**
- Validates refresh token against stored database record
- Checks IP address match with original token
- Revokes old refresh token automatically
- Creates new refresh token with current IP/device info

### POST /auth/request-reset-password
Request password reset token.

**Rate Limit:** 5 attempts per 15 minutes per IP

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "If an account with that email exists, a password reset link has been sent",
  "resetToken": "reset_token_for_development"
}
```

**Note:** `resetToken` is only included in development mode for testing.

### POST /auth/reset-password
Reset password using reset token.

**Rate Limit:** 3 attempts per hour per IP

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "newPassword": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Password reset successful"
}
```

**Security Features:**
- Validates reset token and expiration
- Revokes all existing refresh tokens for security
- Logs security event for monitoring

## Protected Endpoints

### GET /auth/profile
Get current user profile information.

**Authentication:** Required

**Response (200):**
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "isActive": true,
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-01-01T00:00:00.000Z",
      "lastLogin": "2025-01-01T00:00:00.000Z"
    }
  }
}
```

### GET /auth/sessions
Get all active sessions for the current user.

**Authentication:** Required

**Response (200):**
```json
{
  "success": true,
  "message": "Active sessions retrieved successfully",
  "data": {
    "sessions": [
      {
        "id": "session_id_1",
        "ipAddress": "192.168.1.1",
        "userAgent": "Chrome/91.0.4472.124",
        "createdAt": "2025-01-01T00:00:00.000Z",
        "isCurrent": true
      },
      {
        "id": "session_id_2",
        "ipAddress": "10.0.0.1",
        "userAgent": "Firefox/89.0",
        "createdAt": "2024-12-31T23:00:00.000Z",
        "isCurrent": false
      }
    ]
  }
}
```

### DELETE /auth/sessions/:sessionId
Revoke a specific session.

**Authentication:** Required

**Parameters:**
- `sessionId`: The ID of the session to revoke

**Response (200):**
```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

**Error Response (404):**
```json
{
  "success": false,
  "message": "Session not found"
}
```

### POST /auth/logout
Logout from current session.

**Authentication:** Optional (can work without token)

**Request Body:**
```json
{
  "refreshToken": "jwt_refresh_token"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### POST /auth/logout-all
Logout from all devices (revoke all refresh tokens).

**Authentication:** Required

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out from all devices successfully"
}
```

## Rate Limiting

### Rate Limit Headers
When rate limits are applied, responses include headers:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1640995200
```

### Rate Limit Response (429)
```json
{
  "success": false,
  "message": "Too many attempts. Please try again later.",
  "retryAfter": 900
}
```

## Security Headers

All responses include security headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 201 | Created (Registration successful) |
| 400 | Bad Request (Validation errors) |
| 401 | Unauthorized (Invalid credentials) |
| 403 | Forbidden (Invalid/expired token) |
| 404 | Not Found (Resource not found) |
| 429 | Too Many Requests (Rate limited) |
| 500 | Internal Server Error |

## Common Error Scenarios

### Invalid Token (401)
```json
{
  "success": false,
  "message": "Access token required"
}
```

### Expired Token (401)
```json
{
  "success": false,
  "message": "Token expired"
}
```

### Validation Error (400)
```json
{
  "success": false,
  "message": "Validation error",
  "errors": [
    {
      "field": "email",
      "message": "Please provide a valid email address"
    },
    {
      "field": "password",
      "message": "Password must be at least 8 characters long"
    }
  ]
}
```

### Rate Limited (429)
```json
{
  "success": false,
  "message": "Too many attempts. Please try again later.",
  "retryAfter": 900
}
```

## Testing Examples

### Using cURL

**Register User:**
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "firstName": "Test",
    "lastName": "User"
  }'
```

**Login User:**
```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!"
  }'
```

**Get Profile:**
```bash
curl -X GET http://localhost:3001/api/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using JavaScript/Fetch

**Register User:**
```javascript
const response = await fetch('http://localhost:3001/api/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'test@example.com',
    password: 'TestPassword123!',
    firstName: 'Test',
    lastName: 'User'
  })
});

const data = await response.json();
```

**Login and Store Tokens:**
```javascript
const loginResponse = await fetch('http://localhost:3001/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'test@example.com',
    password: 'TestPassword123!'
  })
});

const { data } = await loginResponse.json();
localStorage.setItem('accessToken', data.accessToken);
localStorage.setItem('refreshToken', data.refreshToken);
```

**Authenticated Request:**
```javascript
const profileResponse = await fetch('http://localhost:3001/api/auth/profile', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('accessToken')}`
  }
});

const profileData = await profileResponse.json();
```
