const AuthorizedIP = require('../models/AuthorizedIP');
const Logger = require('../utils/logger');

// Middleware to check if IP is authorized for specific operations
const requireAuthorizedIP = (operation = 'changeUserRole') => {
  return async (req, res, next) => {
    try {
      // Get client IP address
      const clientIP = req.ip || 
                      req.connection.remoteAddress || 
                      req.socket.remoteAddress ||
                      (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                      req.headers['x-real-ip'];

      // Normalize localhost variations
      const normalizedIP = clientIP === '127.0.0.1' || clientIP === '::1' ? 'localhost' : clientIP;
      
      Logger.info('IP authorization check', {
        operation,
        clientIP,
        normalizedIP,
        userId: req.user?.id,
        endpoint: req.originalUrl,
        userAgent: req.get('User-Agent')
      });

      // Check if IP is authorized
      const authResult = await AuthorizedIP.isAuthorized(normalizedIP, operation);
      
      if (!authResult.authorized) {
        Logger.security('Unauthorized IP access attempt', 'high', {
          operation,
          clientIP: normalizedIP,
          reason: authResult.reason,
          userId: req.user?.id,
          endpoint: req.originalUrl,
          userAgent: req.get('User-Agent')
        });

        return res.status(403).json({
          success: false,
          message: 'Access denied: IP not authorized for this operation',
          code: 'IP_NOT_AUTHORIZED',
          reason: authResult.reason
        });
      }

      // Record usage
      try {
        const usageResult = await authResult.authorizedIP.recordUsage(operation);
        
        Logger.audit('Authorized IP operation', operation, {
          clientIP: normalizedIP,
          userId: req.user?.id,
          dailyUsageRemaining: usageResult.dailyUsageRemaining,
          totalUsage: usageResult.totalUsage
        });

        // Add IP info to request for logging
        req.authorizedIP = {
          id: authResult.authorizedIP._id,
          ipAddress: normalizedIP,
          description: authResult.authorizedIP.description,
          dailyUsageRemaining: usageResult.dailyUsageRemaining
        };

      } catch (usageError) {
        Logger.error('Failed to record IP usage', {
          error: usageError.message,
          clientIP: normalizedIP,
          operation
        });
      }

      next();
    } catch (error) {
      Logger.error('IP authorization middleware error', {
        error: error.message,
        stack: error.stack,
        operation,
        clientIP: req.ip
      });

      res.status(500).json({
        success: false,
        message: 'IP authorization check failed',
        code: 'IP_AUTH_ERROR'
      });
    }
  };
};

// Middleware to require super admin role
const requireSuperAdmin = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Check if user has super_admin role
    if (req.user.role !== 'super_admin') {
      Logger.security('Non-super-admin attempted secure operation', 'high', {
        userId: req.user.id,
        userRole: req.user.role,
        endpoint: req.originalUrl,
        clientIP: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Super admin privileges required',
        code: 'SUPER_ADMIN_REQUIRED'
      });
    }

    next();
  } catch (error) {
    Logger.error('Super admin check failed', {
      error: error.message,
      userId: req.user?.id
    });

    res.status(500).json({
      success: false,
      message: 'Authorization check failed',
      code: 'AUTH_CHECK_ERROR'
    });
  }
};

// Middleware to log sensitive operations
const logSensitiveOperation = (operationType) => {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Override res.json to capture response
    const originalJson = res.json;
    res.json = function(data) {
      const duration = Date.now() - startTime;
      
      Logger.security('Sensitive operation completed', 'medium', {
        operationType,
        userId: req.user?.id,
        targetUserId: req.body?.userId || req.params?.userId,
        clientIP: req.authorizedIP?.ipAddress,
        success: data.success,
        duration: `${duration}ms`,
        responseCode: res.statusCode
      });
      
      return originalJson.call(this, data);
    };
    
    Logger.security('Sensitive operation started', 'medium', {
      operationType,
      userId: req.user?.id,
      targetUserId: req.body?.userId || req.params?.userId,
      clientIP: req.authorizedIP?.ipAddress,
      endpoint: req.originalUrl
    });
    
    next();
  };
};

module.exports = {
  requireAuthorizedIP,
  requireSuperAdmin,
  logSensitiveOperation
}; 