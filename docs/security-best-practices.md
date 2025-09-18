# Security Best Practices

## Overview

This document outlines security best practices for deploying, configuring, and maintaining the Auth Server in production environments.

## 1. Environment Security

### Secret Management
```bash
# ❌ Bad: Weak or predictable secrets
JWT_SECRET=mysecret
JWT_REFRESH_SECRET=myrefreshsecret

# ✅ Good: Strong, randomly generated secrets
JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
JWT_REFRESH_SECRET=z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1
```

### Generate Strong Secrets
```bash
# Generate 256-bit secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Or use OpenSSL
openssl rand -hex 32
```

### Environment Isolation
- **Never** share secrets between environments
- Use separate databases for dev/staging/prod
- Implement proper CI/CD secret management
- Rotate secrets regularly (quarterly recommended)

## 2. Database Security

### Connection Security
```bash
# ✅ Use encrypted connections
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db?ssl=true

# ✅ Strong database passwords
MONGODB_URI=mongodb+srv://user:Str0ng_P%40ssw0rd_123@cluster.mongodb.net/db

# ✅ Restrict database access by IP
# Configure MongoDB Atlas IP whitelist
```

### Database Configuration
- Enable MongoDB authentication
- Use dedicated database users with minimal permissions
- Enable audit logging
- Regular database backups
- Monitor database access patterns

## 3. JWT Token Security

### Token Configuration
```bash
# ✅ Short-lived access tokens
JWT_EXPIRES_IN=15m  # or 1h max

# ✅ Reasonable refresh token lifetime
JWT_REFRESH_EXPIRES_IN=7d  # or 30d max

# ✅ Strong salt rounds (production)
BCRYPT_SALT_ROUNDS=12  # or higher for sensitive applications
```

### Token Best Practices
- **Never** store JWT tokens in localStorage (XSS vulnerability)
- Use httpOnly cookies for token storage when possible
- Implement token rotation on refresh
- Validate token claims thoroughly
- Use different secrets for access and refresh tokens

## 4. Rate Limiting & DDoS Protection

### Production Rate Limits
```javascript
// Strict production limits
const productionLimits = {
  login: { attempts: 3, window: '15m' },
  register: { attempts: 2, window: '1h' },
  resetPassword: { attempts: 2, window: '1h' },
  general: { requests: 50, window: '15m' }
};
```

### Advanced Protection
- Implement progressive delays for failed attempts
- Use CAPTCHA after multiple failures
- Deploy behind CDN with DDoS protection
- Monitor for unusual traffic patterns

## 5. Input Validation & Sanitization

### Validation Rules
```javascript
// Strong password requirements
const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .required();

// Email validation with domain restrictions (if needed)
const emailSchema = Joi.string()
  .email()
  .max(254)
  .lowercase()
  .required();
```

### Sanitization
- Sanitize all user inputs
- Validate file uploads strictly
- Implement content security policy (CSP)
- Use parameterized queries (MongoDB prevents injection by default)

## 6. Session Security

### Session Management
```javascript
// Session configuration
const sessionConfig = {
  maxActiveSessions: 5,
  sessionTimeout: '24h',
  forceLogoutOnSuspicious: true,
  trackDeviceFingerprints: true
};
```

### Best Practices
- Limit concurrent sessions per user
- Implement session timeout
- Force logout on password change
- Monitor session anomalies
- Provide session management UI for users

## 7. Monitoring & Alerting

### Security Events to Monitor
```javascript
const securityEvents = [
  'failed_login_attempts',
  'suspicious_ip_activity',
  'token_theft_attempts',
  'password_reset_abuse',
  'account_enumeration',
  'brute_force_attacks',
  'privilege_escalation'
];
```

### Alerting Setup
```bash
# Critical alerts (immediate response)
- Multiple failed logins from single IP
- High-risk login patterns
- Database connection failures
- Memory/CPU threshold breaches

# Warning alerts (investigate within hours)
- Unusual login patterns
- New device registrations
- Password reset spikes
- Performance degradation
```

## 8. Network Security

### HTTPS Configuration
```bash
# ✅ Force HTTPS in production
NODE_ENV=production  # Enables secure headers

# ✅ HSTS headers
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Security Headers
```javascript
// Comprehensive security headers
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'"
  });
  next();
});
```

## 9. Error Handling Security

### Secure Error Messages
```javascript
// ❌ Bad: Reveals system information
if (user.password !== password) {
  return res.status(401).json({ error: 'Invalid password for user@example.com' });
}

// ✅ Good: Generic error message
if (!isValidCredentials) {
  return res.status(401).json({ error: 'Invalid email or password' });
}
```

### Error Logging
- Log detailed errors server-side
- Return generic errors to clients
- Don't expose stack traces in production
- Monitor error patterns for attacks

## 10. Deployment Security

### Production Checklist
- [ ] Environment variables properly configured
- [ ] Database access restricted by IP
- [ ] HTTPS enabled with valid certificates
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Monitoring and alerting setup
- [ ] Regular security updates scheduled
- [ ] Backup and recovery procedures tested

### Container Security (Docker)
```dockerfile
# Use specific versions, not 'latest'
FROM node:18.17.0-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Don't run as root
USER nodejs
```

## 11. Compliance & Auditing

### Data Protection
- Implement GDPR compliance features
- Provide user data export/deletion
- Log all data access events
- Encrypt sensitive data at rest
- Regular security audits

### Audit Logging
```javascript
// Comprehensive audit trail
const auditLog = {
  userId: user._id,
  action: 'LOGIN_SUCCESS',
  ipAddress: req.ip,
  userAgent: req.get('User-Agent'),
  timestamp: new Date(),
  sessionId: session._id,
  riskLevel: 'LOW'
};
```

## 12. Incident Response

### Security Incident Procedures
1. **Detection**: Automated monitoring alerts
2. **Assessment**: Determine severity and scope
3. **Containment**: Isolate affected systems
4. **Investigation**: Analyze logs and evidence
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Update security measures

### Emergency Actions
```javascript
// Emergency user lockout
async function emergencyLockout(userId, reason) {
  await User.updateOne(
    { _id: userId },
    { $set: { isActive: false, lockReason: reason } }
  );
  
  await RefreshToken.revokeAllUserTokens(userId);
  
  Logger.error('Emergency lockout executed', { userId, reason });
}
```

## 13. Regular Maintenance

### Security Updates
- Monitor security advisories for dependencies
- Update packages regularly
- Test security patches in staging
- Maintain update logs

### Security Reviews
- Quarterly security assessments
- Annual penetration testing
- Code security reviews
- Dependency vulnerability scans

### Backup & Recovery
- Regular database backups
- Test backup restoration procedures
- Document recovery processes
- Maintain offline backup copies

## 14. Development Security

### Secure Development Practices
```javascript
// ✅ Use environment-specific configurations
if (process.env.NODE_ENV === 'development') {
  // Development-only features
} else {
  // Production security measures
}

// ✅ Validate all inputs
const { error } = schema.validate(req.body);
if (error) {
  return res.status(400).json({ error: 'Validation failed' });
}
```

### Code Security
- Regular dependency updates
- Static code analysis
- Security-focused code reviews
- Automated security testing

## 15. Monitoring Dashboard

### Key Metrics to Track
```javascript
const securityMetrics = {
  failedLogins: 'count per hour',
  suspiciousIPs: 'unique IPs flagged',
  activeTokens: 'total valid tokens',
  sessionDuration: 'average session length',
  passwordResets: 'requests per day',
  accountLockouts: 'temporary locks',
  errorRate: 'percentage of failed requests'
};
```

### Alerting Thresholds
```javascript
const alertThresholds = {
  failedLogins: { warning: 10, critical: 50 },
  suspiciousIPs: { warning: 5, critical: 20 },
  errorRate: { warning: 5, critical: 10 },
  responseTime: { warning: 1000, critical: 3000 }
};
```

## Conclusion

Security is an ongoing process that requires:
- Regular updates and maintenance
- Continuous monitoring and alerting
- Incident response preparedness
- Team security awareness
- Regular security assessments

Follow these practices to maintain a secure authentication system that protects user data and prevents unauthorized access.
