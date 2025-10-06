const Permission = require('../models/Permission');
const Resource = require('../models/Resource');
const Logger = require('../utils/logger');

// Main RBAC middleware factory
const requirePermission = (resourceName, requiredPermission = 'read', options = {}) => {
  return async (req, res, next) => {
    try {
      // Extract user info from JWT token
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required for permission check',
          code: 'AUTH_REQUIRED'
        });
      }

      const userId = req.user.id;
      const subaccountId = options.extractSubaccountId ? 
        options.extractSubaccountId(req) : 
        req.params.subaccountId || req.body.subaccountId || null;

      Logger.debug('RBAC permission check', {
        userId,
        resourceName,
        requiredPermission,
        subaccountId,
        endpoint: req.originalUrl,
        method: req.method
      });

      // Check permission
      const permissionResult = await Permission.checkPermission(
        userId,
        resourceName,
        requiredPermission,
        subaccountId
      );

      if (!permissionResult.hasPermission) {
        Logger.security('Permission denied', 'medium', {
          userId,
          userEmail: req.user.email,
          userRole: req.user.role,
          resourceName,
          requiredPermission,
          subaccountId,
          reason: permissionResult.reason,
          endpoint: req.originalUrl,
          method: req.method,
          clientIP: req.ip
        });

        return res.status(403).json({
          success: false,
          message: permissionResult.reason || 'Permission denied',
          code: 'PERMISSION_DENIED',
          details: {
            resource: resourceName,
            requiredPermission,
            userRole: req.user.role,
            effectiveRole: permissionResult.effectiveRole
          }
        });
      }

      // Permission granted - add permission info to request
      req.permission = {
        resourceName,
        requiredPermission,
        effectiveRole: permissionResult.effectiveRole,
        reason: permissionResult.reason,
        subaccountId,
        permissionId: permissionResult.permissionId
      };

      Logger.audit('Permission granted', resourceName, {
        userId,
        requiredPermission,
        effectiveRole: permissionResult.effectiveRole,
        reason: permissionResult.reason,
        subaccountId
      });

      next();
    } catch (error) {
      Logger.error('RBAC middleware error', {
        error: error.message,
        stack: error.stack,
        userId: req.user?.id,
        resourceName,
        requiredPermission
      });

      res.status(500).json({
        success: false,
        message: 'Permission check failed',
        code: 'RBAC_ERROR'
      });
    }
  };
};

// Middleware to require specific role (global or effective)
const requireRole = (requiredRole, options = {}) => {
  return async (req, res, next) => {
    try {
      // Service token authentication bypasses role check (service is already trusted)
      if (req.service && req.service.authenticated) {
        req.roleCheck = {
          passed: true,
          effectiveRole: 'service',
          reason: 'Service token authentication',
          serviceName: req.service.name
        };
        return next();
      }

      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required for role check',
          code: 'AUTH_REQUIRED'
        });
      }

      const userId = req.user.id;
      const userGlobalRole = req.user.role;
      const subaccountId = options.extractSubaccountId ? 
        options.extractSubaccountId(req) : 
        (req.params && req.params.subaccountId) || 
        (req.body && req.body.subaccountId) || 
        (req.query && req.query.subaccountId) || 
        null;

      // Super admin always passes
      if (userGlobalRole === 'super_admin') {
        req.roleCheck = {
          passed: true,
          effectiveRole: 'super_admin',
          reason: 'Super admin access'
        };
        return next();
      }

      // Global admin check
      if (userGlobalRole === 'admin' && (requiredRole === 'admin' || requiredRole === 'user')) {
        req.roleCheck = {
          passed: true,
          effectiveRole: 'admin',
          reason: 'Global admin access'
        };
        return next();
      }

      // Check subaccount-specific role if subaccount context exists
      if (subaccountId) {
        const UserSubaccount = require('../models/UserSubaccount');
        const userSubaccount = await UserSubaccount.findOne({
          userId,
          subaccountId,
          isActive: true
        });

        if (userSubaccount) {
          const subaccountRole = userSubaccount.role;
          
          // Check if subaccount role meets requirement
          const roleHierarchy = ['viewer', 'editor', 'admin', 'owner'];
          const requiredIndex = roleHierarchy.indexOf(requiredRole);
          const userIndex = roleHierarchy.indexOf(subaccountRole);
          
          if (userIndex >= requiredIndex) {
            req.roleCheck = {
              passed: true,
              effectiveRole: subaccountRole,
              reason: 'Subaccount role sufficient',
              subaccountRole
            };
            return next();
          }
        }
      }

      // Check global role as fallback
      const roleHierarchy = ['user', 'admin', 'super_admin'];
      const requiredIndex = roleHierarchy.indexOf(requiredRole);
      const userIndex = roleHierarchy.indexOf(userGlobalRole);
      
      if (userIndex >= requiredIndex) {
        req.roleCheck = {
          passed: true,
          effectiveRole: userGlobalRole,
          reason: 'Global role sufficient'
        };
        return next();
      }

      // Role check failed
      Logger.security('Role check failed', 'medium', {
        userId,
        userEmail: req.user.email,
        userGlobalRole,
        requiredRole,
        subaccountId,
        endpoint: req.originalUrl,
        clientIP: req.ip
      });

      res.status(403).json({
        success: false,
        message: `${requiredRole} role required`,
        code: 'INSUFFICIENT_ROLE',
        details: {
          userRole: userGlobalRole,
          requiredRole,
          subaccountId
        }
      });

    } catch (error) {
      Logger.error('Role check middleware error', {
        error: error.message,
        userId: req.user?.id,
        requiredRole
      });

      res.status(500).json({
        success: false,
        message: 'Role check failed',
        code: 'ROLE_CHECK_ERROR'
      });
    }
  };
};

// Middleware to check resource-specific permissions by endpoint
const requireResourcePermission = (requiredPermission = 'read', options = {}) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const serviceName = options.serviceName || 'auth-server';
      const method = req.method;
      const path = req.route?.path || req.originalUrl;

      // Find resource by endpoint
      const resource = await Resource.findByEndpoint(method, path, serviceName);
      
      if (!resource) {
        // If no resource is defined, check if we should allow or deny by default
        if (options.allowUnprotectedEndpoints) {
          Logger.debug('No resource protection defined for endpoint, allowing access', {
            method,
            path,
            serviceName,
            userId: req.user.id
          });
          return next();
        } else {
          Logger.security('Unprotected endpoint accessed', 'low', {
            method,
            path,
            serviceName,
            userId: req.user.id,
            endpoint: req.originalUrl
          });
          
          return res.status(403).json({
            success: false,
            message: 'Endpoint not protected by RBAC system',
            code: 'UNPROTECTED_ENDPOINT'
          });
        }
      }

      // Get required permissions from resource definition
      const endpointPermissions = resource.getRequiredPermissions(method, path);
      const actualRequiredPermission = endpointPermissions.includes(requiredPermission) ? 
        requiredPermission : endpointPermissions[0];

      // Use the resource-based permission check
      return requirePermission(resource.name, actualRequiredPermission, options)(req, res, next);

    } catch (error) {
      Logger.error('Resource permission middleware error', {
        error: error.message,
        userId: req.user?.id,
        endpoint: req.originalUrl
      });

      res.status(500).json({
        success: false,
        message: 'Resource permission check failed',
        code: 'RESOURCE_PERMISSION_ERROR'
      });
    }
  };
};

// Middleware to require admin role OR accessing own data
const requireAdminOrSelf = (userIdParam = 'userId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const authenticatedUserId = req.user.id;
      const targetUserId = req.params[userIdParam];
      const userRole = req.user.role;

      // Allow if user is super_admin or admin
      if (userRole === 'super_admin' || userRole === 'admin') {
        req.accessReason = 'admin_access';
        return next();
      }

      // Allow if user is accessing their own data
      if (authenticatedUserId === targetUserId) {
        req.accessReason = 'self_access';
        return next();
      }

      // Access denied
      Logger.security('Unauthorized access attempt to user data', 'medium', {
        userId: authenticatedUserId,
        userEmail: req.user.email,
        targetUserId,
        userRole,
        endpoint: req.originalUrl,
        clientIP: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Access denied. Admin role required or you can only access your own data.',
        code: 'ACCESS_DENIED',
        details: {
          reason: 'Insufficient permissions to access other user data'
        }
      });

    } catch (error) {
      Logger.error('requireAdminOrSelf middleware error', {
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
};

// Utility function to extract subaccount ID from different request patterns
const extractSubaccountId = {
  fromParams: (req) => req.params.subaccountId,
  fromBody: (req) => req.body.subaccountId,
  fromQuery: (req) => req.query.subaccountId,
  fromHeader: (headerName = 'x-subaccount-id') => (req) => req.headers[headerName],
  custom: (extractorFn) => extractorFn
};

// Pre-built permission checks for common operations
const commonPermissions = {
  // Subaccount operations
  subaccount: {
    read: requirePermission('subaccount_management', 'read'),
    write: requirePermission('subaccount_management', 'write'),
    admin: requirePermission('subaccount_management', 'admin')
  },
  
  // Database operations
  database: {
    read: requirePermission('database_operations', 'read'),
    write: requirePermission('database_operations', 'write'),
    delete: requirePermission('database_operations', 'delete')
  },
  
  // User management
  users: {
    read: requirePermission('user_management', 'read'),
    write: requirePermission('user_management', 'write'),
    admin: requirePermission('user_management', 'admin')
  },
  
  // System administration
  system: {
    admin: requirePermission('system_admin', 'admin')
  }
};

module.exports = {
  requirePermission,
  requireRole,
  requireResourcePermission,
  extractSubaccountId,
  commonPermissions,
  requireAdminOrSelf
}; 