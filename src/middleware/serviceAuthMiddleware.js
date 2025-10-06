const { validateServiceToken } = require('../controllers/serviceTokenController');
const Logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');
const config = require('../../config/config');

// Service token authentication middleware
const authenticateServiceToken = async (req, res, next) => {
  try {
    const serviceToken = req.headers['x-service-token'];
    
    if (!serviceToken) {
      return res.status(401).json({
        success: false,
        message: 'Service token required',
        code: 'SERVICE_TOKEN_REQUIRED'
      });
    }

    // Validate service token
    const tokenInfo = await validateServiceToken(serviceToken);
    
    if (!tokenInfo) {
      Logger.security('Invalid service token', 'high', {
        token: serviceToken.substring(0, 8) + '***',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        message: 'Invalid or expired service token',
        code: 'INVALID_SERVICE_TOKEN'
      });
    }

    // Check IP restrictions if configured
    if (tokenInfo.allowedIPs && tokenInfo.allowedIPs.length > 0) {
      const clientIP = req.ip || req.connection.remoteAddress;
      if (!tokenInfo.allowedIPs.includes(clientIP)) {
        Logger.security('Service token used from unauthorized IP', 'high', {
          serviceName: tokenInfo.serviceName,
          clientIP,
          allowedIPs: tokenInfo.allowedIPs,
          endpoint: req.originalUrl
        });

        return res.status(403).json({
          success: false,
          message: 'Access denied from this IP address',
          code: 'IP_NOT_ALLOWED'
        });
      }
    }

    // Add service info to request
    req.service = {
      name: tokenInfo.serviceName,
      permissions: tokenInfo.permissions,
      rateLimit: tokenInfo.rateLimit
    };

    req.requestId = uuidv4();

    Logger.debug('Service authenticated', {
      service: tokenInfo.serviceName,
      requestId: req.requestId,
      permissions: tokenInfo.permissions
    });

    next();

  } catch (error) {
    Logger.error('Service authentication failed', {
      error: error.message,
      endpoint: req.originalUrl,
      ip: req.ip
    });

    return res.status(500).json({
      success: false,
      message: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

// Check if service has specific permission
const requireServicePermission = (permission) => {
  return (req, res, next) => {
    if (!req.service) {
      return res.status(401).json({
        success: false,
        message: 'Service authentication required',
        code: 'SERVICE_AUTH_REQUIRED'
      });
    }

    if (!req.service.permissions.includes(permission) && !req.service.permissions.includes('*')) {
      Logger.security('Service permission denied', 'medium', {
        service: req.service.name,
        requiredPermission: permission,
        servicePermissions: req.service.permissions,
        endpoint: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        message: `Permission '${permission}' required`,
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    next();
  };
};

// Combined middleware that accepts both JWT tokens and service tokens
const authenticateTokenOrService = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const serviceToken = req.headers['x-service-token'];

  // If service token is provided, use service authentication
  if (serviceToken) {
    return authenticateServiceToken(req, res, next);
  }

  // If JWT token is provided, use JWT authentication
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const { authenticateToken } = require('./authMiddleware');
    return authenticateToken(req, res, next);
  }

  // No authentication provided
  return res.status(401).json({
    success: false,
    message: 'Authentication required (JWT token or service token)',
    code: 'AUTH_REQUIRED'
  });
};

// Simple tenant manager service token validation middleware
// Validates X-Service-Token against TENANT_MANAGER_SERVICE_TOKEN from config
const authenticateTenantManagerToken = (req, res, next) => {
  try {
    const serviceToken = req.headers['x-service-token'];
    const userId = req.headers['x-user-id'];
    const serviceName = req.headers['x-service-name'];

    if (!serviceToken) {
      return res.status(401).json({
        success: false,
        message: 'Service token required',
        code: 'SERVICE_TOKEN_REQUIRED'
      });
    }

    // Validate against config
    if (serviceToken !== config.serviceTokens.tenantManager) {
      Logger.security('Invalid tenant manager service token', 'high', {
        token: serviceToken.substring(0, 8) + '***',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        message: 'Invalid service token',
        code: 'INVALID_SERVICE_TOKEN'
      });
    }

    // Add service info to request
    req.service = {
      name: serviceName || 'tenant-manager',
      userId: userId || null,
      authenticated: true
    };

    // If userId is provided, add it to req.user for compatibility with existing code
    if (userId) {
      req.user = { id: userId };
    }

    Logger.debug('Tenant manager service authenticated', {
      service: req.service.name,
      userId: req.service.userId,
      endpoint: req.originalUrl
    });

    next();

  } catch (error) {
    Logger.error('Service authentication failed', {
      error: error.message,
      endpoint: req.originalUrl,
      ip: req.ip
    });

    return res.status(500).json({
      success: false,
      message: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

// Combined middleware for JWT token or tenant manager service token
const authenticateTokenOrTenantManager = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const serviceToken = req.headers['x-service-token'];

  // If service token is provided, use tenant manager authentication
  if (serviceToken) {
    return authenticateTenantManagerToken(req, res, next);
  }

  // If JWT token is provided, use JWT authentication
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const { authenticateToken } = require('./authMiddleware');
    return authenticateToken(req, res, next);
  }

  // No authentication provided
  return res.status(401).json({
    success: false,
    message: 'Authentication required (JWT token or service token)',
    code: 'AUTH_REQUIRED'
  });
};

module.exports = {
  authenticateServiceToken,
  requireServicePermission,
  authenticateTokenOrService,
  authenticateTenantManagerToken,
  authenticateTokenOrTenantManager
}; 