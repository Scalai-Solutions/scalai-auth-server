# Auth Server Documentation

## Overview

The Auth Server is a comprehensive authentication service built with Node.js, Express, and MongoDB. It provides enterprise-grade security features including JWT-based authentication, IP tracking, suspicious activity detection, and session management.

## Table of Contents

1. [Security Features](./security-features.md)
2. [API Documentation](./api-documentation.md)
3. [Configuration Guide](./configuration.md)
4. [Deployment Guide](./deployment.md)
5. [Security Best Practices](./security-best-practices.md)
6. [Troubleshooting](./troubleshooting.md)

## Quick Start

### Prerequisites
- Node.js v16+
- MongoDB Atlas account or local MongoDB instance
- npm or yarn

### Installation

```bash
cd auth-server
npm install
```

### Environment Setup

Copy and configure your environment variables:

```bash
# Copy example env file
cp .env.example .env

# Edit with your MongoDB credentials
nano .env
```

### Running the Server

```bash
# Development mode
npm run dev

# Production mode
npm start

# Clear database and start (development only)
npm run dev:clear
```

## Architecture

```
auth-server/
├── src/
│   ├── controllers/     # Request handlers
│   ├── middleware/      # Authentication & security middleware
│   ├── models/         # MongoDB models
│   ├── routes/         # API routes
│   ├── utils/          # Utility functions
│   └── validators/     # Request validation
├── config/
│   └── config.js       # Environment configuration
├── docs/               # Documentation
└── tests/              # Test files
```

## Key Features

- 🔐 **JWT Authentication** with access & refresh tokens
- 🛡️ **Advanced Security** with IP tracking and suspicious activity detection
- 📊 **Session Management** with device tracking
- 🚫 **Rate Limiting** for sensitive operations
- 📝 **Comprehensive Logging** for security monitoring
- 🗄️ **MongoDB Integration** with proper indexing
- ⚡ **High Performance** with connection pooling

## Security Highlights

- IP address tracking for all authentication events
- Suspicious activity detection with risk assessment
- Session management with device fingerprinting
- Rate limiting for brute force protection
- Security alerts and monitoring
- Refresh token rotation and validation

## Support

For issues, questions, or contributions, please refer to the individual documentation files or create an issue in the project repository.
