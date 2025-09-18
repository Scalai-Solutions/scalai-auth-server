# Configuration Guide

## Environment Variables

### Required Variables

#### Server Configuration
```bash
# Server port (default: 3001)
PORT=3001

# Environment mode (development, production, test)
NODE_ENV=development
```

#### JWT Configuration
```bash
# JWT secret for access tokens (REQUIRED)
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production

# Access token expiration (default: 24h)
JWT_EXPIRES_IN=24h

# JWT secret for refresh tokens (REQUIRED)
JWT_REFRESH_SECRET=your_super_secret_refresh_jwt_key_change_this_in_production

# Refresh token expiration (default: 7d)
JWT_REFRESH_EXPIRES_IN=7d
```

#### Database Configuration
```bash
# MongoDB connection URI (REQUIRED)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database?retryWrites=true&w=majority

# Database name (default: scalai_auth)
DB_NAME=scalai_auth
```

#### Security Configuration
```bash
# bcrypt salt rounds (default: 12)
BCRYPT_SALT_ROUNDS=12

# CORS origin (default: http://localhost:3000)
CORS_ORIGIN=http://localhost:3000
```

### Optional Variables

#### Email Configuration (for password reset)
```bash
# SMTP settings for email notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Email templates
FROM_EMAIL=noreply@yourapp.com
FROM_NAME=YourApp Security
```

#### Security Enhancement
```bash
# Rate limiting settings
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100

# Session settings
SESSION_TIMEOUT_HOURS=24
MAX_SESSIONS_PER_USER=5

# Security monitoring
ENABLE_SECURITY_ALERTS=true
ALERT_WEBHOOK_URL=https://hooks.slack.com/your-webhook
```

## Configuration File Structure

### config/config.js
```javascript
require('dotenv').config();

const config = {
  server: {
    port: process.env.PORT || 3001,
    nodeEnv: process.env.NODE_ENV || 'development'
  },
  
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  },
  
  database: {
    mongoUri: process.env.MONGODB_URI,
    dbName: process.env.DB_NAME || 'scalai_auth'
  },
  
  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
  },
  
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000'
  },
  
  email: {
    smtp: {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    from: {
      email: process.env.FROM_EMAIL,
      name: process.env.FROM_NAME
    }
  }
};

// Validate required configuration
const requiredConfig = [
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'MONGODB_URI'
];

requiredConfig.forEach(key => {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
});

module.exports = config;
```

## Environment-Specific Configurations

### Development (.env.development)
```bash
NODE_ENV=development
PORT=3001

# Use development-specific secrets (shorter, simpler)
JWT_SECRET=dev_jwt_secret_key
JWT_REFRESH_SECRET=dev_refresh_secret_key

# Local or development MongoDB
MONGODB_URI=mongodb://localhost:27017/scalai_auth_dev
DB_NAME=scalai_auth_dev

# Relaxed security for development
BCRYPT_SALT_ROUNDS=4
CORS_ORIGIN=http://localhost:3000

# Enable debug logging
DEBUG=auth:*
LOG_LEVEL=debug
```

### Production (.env.production)
```bash
NODE_ENV=production
PORT=3001

# Strong, randomly generated secrets
JWT_SECRET=your_256_bit_random_secret_key_here
JWT_REFRESH_SECRET=your_256_bit_random_refresh_secret_key_here

# Production MongoDB Atlas
MONGODB_URI=mongodb+srv://prod_user:strong_password@cluster.mongodb.net/scalai_auth_prod?retryWrites=true&w=majority
DB_NAME=scalai_auth_prod

# Strong security settings
BCRYPT_SALT_ROUNDS=12
CORS_ORIGIN=https://yourapp.com

# Production email settings
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=your_sendgrid_api_key

FROM_EMAIL=security@yourapp.com
FROM_NAME=YourApp Security Team

# Security monitoring
ENABLE_SECURITY_ALERTS=true
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Performance settings
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=50
```

### Testing (.env.test)
```bash
NODE_ENV=test
PORT=3002

# Test-specific secrets
JWT_SECRET=test_jwt_secret
JWT_REFRESH_SECRET=test_refresh_secret

# In-memory or test database
MONGODB_URI=mongodb://localhost:27017/scalai_auth_test
DB_NAME=scalai_auth_test

# Fast settings for testing
BCRYPT_SALT_ROUNDS=1
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=2h

# Disable external services in tests
ENABLE_SECURITY_ALERTS=false
```

## Security Configuration Best Practices

### JWT Secrets
```bash
# Generate strong secrets (256-bit recommended)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Use different secrets for access and refresh tokens
JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
JWT_REFRESH_SECRET=z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1
```

### Password Hashing
```bash
# Development: Fast but less secure
BCRYPT_SALT_ROUNDS=4

# Production: Secure but slower
BCRYPT_SALT_ROUNDS=12

# High-security applications
BCRYPT_SALT_ROUNDS=15
```

### Database Security
```bash
# Use strong database passwords
MONGODB_URI=mongodb+srv://user:Str0ng_P@ssw0rd_123@cluster.mongodb.net/db

# URL encode special characters
# @ becomes %40, : becomes %3A, etc.
MONGODB_URI=mongodb+srv://user:P%40ssw0rd%3A123@cluster.mongodb.net/db
```

## Rate Limiting Configuration

### Default Settings
```javascript
const rateLimitConfig = {
  // General API rate limiting
  general: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100
  },
  
  // Authentication endpoints
  auth: {
    login: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 5
    },
    register: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 3
    },
    resetPassword: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 3
    }
  }
};
```

### Custom Rate Limiting
```bash
# Environment variables for rate limiting
AUTH_LOGIN_RATE_LIMIT_WINDOW=900000    # 15 minutes
AUTH_LOGIN_RATE_LIMIT_MAX=5            # 5 attempts

AUTH_REGISTER_RATE_LIMIT_WINDOW=3600000 # 1 hour
AUTH_REGISTER_RATE_LIMIT_MAX=3          # 3 attempts
```

## CORS Configuration

### Development CORS
```bash
# Allow all origins (development only)
CORS_ORIGIN=*

# Multiple origins
CORS_ORIGIN=http://localhost:3000,http://localhost:3001
```

### Production CORS
```bash
# Single production domain
CORS_ORIGIN=https://yourapp.com

# Multiple production domains
CORS_ORIGIN=https://yourapp.com,https://api.yourapp.com,https://admin.yourapp.com
```

## Logging Configuration

### Log Levels
```bash
# Set log level (error, warn, info, debug)
LOG_LEVEL=info

# Enable specific debug namespaces
DEBUG=auth:security,auth:database

# Disable all logging (production)
SILENT=true
```

### Log Format
```javascript
// Development: Human-readable
if (config.server.nodeEnv === 'development') {
  app.use(morgan('dev'));
} else {
  // Production: JSON format for log aggregation
  app.use(morgan('combined'));
}
```

## Health Check Configuration

### Custom Health Check
```bash
# Health check endpoints
HEALTH_CHECK_PATH=/health
DETAILED_HEALTH_PATH=/health/detailed

# Include sensitive info in health check (development only)
HEALTH_INCLUDE_SENSITIVE=true
```

## Monitoring Configuration

### Security Monitoring
```bash
# Enable security event monitoring
ENABLE_SECURITY_MONITORING=true

# Webhook for security alerts
SECURITY_WEBHOOK_URL=https://hooks.slack.com/your-webhook

# Alert thresholds
SUSPICIOUS_LOGIN_THRESHOLD=3
HIGH_RISK_ALERT_THRESHOLD=5
```

### Performance Monitoring
```bash
# Enable performance monitoring
ENABLE_PERFORMANCE_MONITORING=true

# Response time threshold (ms)
SLOW_REQUEST_THRESHOLD=1000

# Memory usage alert threshold (MB)
MEMORY_ALERT_THRESHOLD=512
```

## Validation and Testing

### Configuration Validation Script
```javascript
// scripts/validate-config.js
const config = require('../config/config');

function validateConfig() {
  const errors = [];
  
  // Check JWT secrets strength
  if (config.jwt.secret.length < 32) {
    errors.push('JWT_SECRET should be at least 32 characters');
  }
  
  // Check bcrypt rounds
  if (config.security.bcryptSaltRounds < 10) {
    errors.push('BCRYPT_SALT_ROUNDS should be at least 10 for production');
  }
  
  // Check database connection
  if (!config.database.mongoUri.includes('mongodb')) {
    errors.push('Invalid MONGODB_URI format');
  }
  
  return errors;
}

const errors = validateConfig();
if (errors.length > 0) {
  console.error('Configuration errors:', errors);
  process.exit(1);
}
```

### Environment Testing
```bash
# Test configuration loading
npm run test:config

# Validate environment variables
npm run validate:env

# Test database connection
npm run test:db
```
