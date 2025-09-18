# Security Features Documentation

## Overview

The Auth Server implements comprehensive security features designed to protect against common attack vectors and provide detailed monitoring of authentication events.

## 1. IP Address Tracking & Validation

### Features
- **Complete IP Logging**: Every authentication event records the client's IP address
- **IP Mismatch Detection**: Validates refresh tokens against original IP addresses
- **Geolocation Change Detection**: Alerts when users access from different locations
- **Forwarded IP Support**: Handles X-Forwarded-For and X-Real-IP headers

### Implementation
```javascript
// Client info extraction
const getClientInfo = (req) => {
  return {
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent') || 'Unknown',
    forwardedFor: req.get('X-Forwarded-For'),
    realIP: req.get('X-Real-IP')
  };
};
```

### Security Benefits
- **Token Theft Detection**: Identifies when tokens are used from different IPs
- **Account Takeover Prevention**: Alerts on suspicious location changes
- **Audit Trail**: Complete logging of access patterns
- **Compliance**: Meets security logging requirements

## 2. Suspicious Activity Detection

### Risk Assessment Algorithm
The system analyzes multiple factors to determine risk levels:

#### Risk Factors
- **Multiple IPs**: More than 3 unique IPs in 24 hours
- **New IP**: Login from previously unseen IP address
- **User Agent Changes**: Multiple different browsers/devices
- **Rapid Location Changes**: Different IPs within 30 minutes

#### Risk Levels
- **Low**: Normal activity patterns
- **Medium**: 1 suspicious flag detected
- **High**: 2+ suspicious flags detected

### Implementation Example
```javascript
const suspiciousActivity = await detectSuspiciousActivity(
  user._id, 
  clientInfo.ipAddress, 
  clientInfo.userAgent
);

if (suspiciousActivity.riskLevel === 'high') {
  // Trigger additional security measures
  await handleSecurityAlert(user, 'high_risk_login', clientInfo);
}
```

## 3. Session Management

### Features
- **Active Session Tracking**: View all active sessions with device info
- **Individual Session Revocation**: Terminate specific sessions
- **Bulk Session Management**: Logout from all devices
- **Device Fingerprinting**: Basic device identification

### API Endpoints
```bash
# Get active sessions
GET /api/auth/sessions

# Revoke specific session
DELETE /api/auth/sessions/:sessionId

# Logout from all devices
POST /api/auth/logout-all
```

### Session Data Structure
```javascript
{
  "id": "session_id",
  "ipAddress": "192.168.1.1",
  "userAgent": "Chrome/91.0",
  "createdAt": "2025-01-01T00:00:00Z",
  "isCurrent": true
}
```

## 4. Rate Limiting & Protection

### Rate Limiting Rules
- **Login Attempts**: 5 attempts per 15 minutes per IP
- **Registration**: 3 attempts per hour per IP
- **Password Reset**: 3 attempts per hour per IP
- **Reset Requests**: 5 attempts per 15 minutes per IP

### Implementation
```javascript
// Apply rate limiting to sensitive endpoints
app.use('/api/auth/login', sensitiveOperationLimiter(5, 15));
app.use('/api/auth/register', sensitiveOperationLimiter(3, 60));
```

### Additional Protections
- **Suspicious IP Detection**: Flags IPs with >10 logins per hour
- **Account Lockout**: Temporary locks after failed attempts
- **Security Headers**: Comprehensive security headers applied

## 5. Token Security

### JWT Implementation
- **Access Tokens**: Short-lived (24 hours) for API access
- **Refresh Tokens**: Long-lived (7 days) stored in database
- **Token Rotation**: New tokens generated on each refresh

### Refresh Token Features
- **Database Storage**: Secure server-side storage with MongoDB
- **IP Validation**: Tokens validated against original IP
- **Automatic Expiry**: TTL indexes for automatic cleanup
- **Revocation Support**: Individual and bulk token revocation

### Token Structure
```javascript
// Access Token Payload
{
  "id": "user_id",
  "email": "user@example.com",
  "iat": 1640995200,
  "exp": 1641081600
}

// Refresh Token Database Record
{
  "token": "unique_token_id",
  "user": "user_object_id",
  "expiresAt": "2025-01-08T00:00:00Z",
  "ipAddress": "192.168.1.1",
  "userAgent": "Chrome/91.0",
  "isRevoked": false
}
```

## 6. Security Monitoring & Alerts

### Event Logging
All security events are logged with structured data:

```javascript
// Login event
Logger.info('User logged in', { 
  userId: user._id, 
  email: user.email,
  ipAddress: clientInfo.ipAddress,
  riskLevel: suspiciousActivity.riskLevel
});

// Security alert
Logger.warn('Security Alert', {
  userId: user._id,
  alertType: 'suspicious_login',
  clientInfo: clientInfo,
  suspiciousActivity: suspiciousActivity
});
```

### Alert Types
- **suspicious_login**: Unusual login patterns detected
- **token_ip_mismatch**: Refresh token used from different IP
- **password_reset**: Password reset completed
- **high_risk_login**: Multiple risk factors detected

### Monitoring Integration
The system is designed to integrate with:
- **Log aggregation** services (ELK Stack, Splunk)
- **Security monitoring** tools (SIEM)
- **Alerting systems** (PagerDuty, Slack)
- **Email notifications** for critical events

## 7. Database Security

### MongoDB Security Features
- **Connection Security**: Encrypted connections with proper authentication
- **Index Optimization**: Proper indexing for performance and security
- **TTL Indexes**: Automatic cleanup of expired tokens
- **Data Validation**: Schema validation for all models

### User Model Security
```javascript
// Password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
});

// Sensitive data exclusion
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.resetPasswordToken;
  return user;
};
```

## 8. Configuration & Environment Security

### Environment Variables
```bash
# JWT Security
JWT_SECRET=your_super_secret_jwt_key
JWT_REFRESH_SECRET=your_super_secret_refresh_jwt_key

# Database Security
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/db

# Security Settings
BCRYPT_SALT_ROUNDS=12
NODE_ENV=production
```

### Security Best Practices
- **Strong Secrets**: Use cryptographically secure random keys
- **Environment Isolation**: Separate configs for dev/staging/prod
- **Secret Management**: Use services like AWS Secrets Manager
- **Regular Rotation**: Rotate secrets periodically

## 9. API Security Response

### Security Info in Responses
Login responses include security information:

```javascript
{
  "success": true,
  "data": {
    "user": { /* user data */ },
    "accessToken": "jwt_token",
    "refreshToken": "refresh_token",
    "securityInfo": {
      "riskLevel": "low",
      "newDevice": false,
      "flags": []
    }
  }
}
```

### Error Handling
Security-conscious error messages:
- **Generic Messages**: Don't reveal system internals
- **Rate Limiting**: Clear retry-after information
- **Validation Errors**: Helpful but not exploitable

## 10. Testing Security Features

### Test Script Usage
```bash
# Run comprehensive security tests
./test-security-features.sh

# Test specific features
curl -X POST /api/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: TestBrowser/1.0" \
  -d '{"email":"test@example.com","password":"password"}'
```

### Security Test Coverage
- IP tracking validation
- Suspicious activity detection
- Rate limiting enforcement
- Session management
- Token validation
- Error handling

## Implementation Notes

### Performance Considerations
- **In-Memory Caching**: Rate limiting uses in-memory storage
- **Database Indexing**: Optimized queries for security checks
- **Connection Pooling**: Efficient database connections

### Scalability
- **Horizontal Scaling**: Stateless design supports load balancing
- **Redis Integration**: Can be added for distributed rate limiting
- **Microservice Ready**: Designed for microservice architecture

### Future Enhancements
- **2FA Integration**: Two-factor authentication support
- **Advanced Geolocation**: IP geolocation services
- **Machine Learning**: AI-based anomaly detection
- **Real-time Alerts**: WebSocket-based security notifications
