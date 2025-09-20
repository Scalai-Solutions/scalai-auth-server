const Resource = require('../models/Resource');
const Permission = require('../models/Permission');
const User = require('../models/User');
const Logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

class RBACController {
  // Create a new resource
  static async createResource(req, res, next) {
    try {
      const {
        name,
        description,
        type,
        service,
        endpoints = [],
        defaultPermissions = {},
        settings = {}
      } = req.body;

      const createdBy = req.user.id;

      Logger.audit('Create resource', 'rbac', {
        userId: createdBy,
        resourceName: name,
        resourceType: type,
        service
      });

      // Check if resource already exists
      const existingResource = await Resource.findOne({ name });
      if (existingResource) {
        return res.status(400).json({
          success: false,
          message: 'Resource with this name already exists',
          code: 'RESOURCE_EXISTS'
        });
      }

      // Create resource
      const resource = new Resource({
        name,
        description,
        type,
        service,
        endpoints,
        defaultPermissions: {
          super_admin: { read: true, write: true, delete: true, admin: true },
          admin: { read: true, write: true, delete: true, admin: false },
          user: { read: false, write: false, delete: false, admin: false },
          ...defaultPermissions
        },
        settings: {
          requiresSubaccount: false,
          globalAdminAccess: true,
          rateLimits: {
            perUser: { requests: 100, windowMs: 60000 },
            perSubaccount: { requests: 1000, windowMs: 60000 }
          },
          ...settings
        },
        createdBy
      });

      await resource.save();

      Logger.info('Resource created successfully', {
        resourceId: resource._id,
        name: resource.name,
        type: resource.type,
        service: resource.service,
        createdBy
      });

      res.status(201).json({
        success: true,
        message: 'Resource created successfully',
        data: resource
      });

    } catch (error) {
      Logger.error('Failed to create resource', {
        error: error.message,
        userId: req.user?.id,
        resourceData: req.body
      });
      next(error);
    }
  }

  // List all resources
  static async listResources(req, res, next) {
    try {
      const { service, type, isActive = true } = req.query;
      
      const query = { isActive };
      if (service) query.service = service;
      if (type) query.type = type;

      const resources = await Resource.find(query)
        .populate('createdBy', 'email firstName lastName')
        .sort({ createdAt: -1 });

      res.json({
        success: true,
        data: {
          resources,
          count: resources.length
        }
      });

    } catch (error) {
      Logger.error('Failed to list resources', {
        error: error.message,
        userId: req.user?.id
      });
      next(error);
    }
  }

  // Grant permission to user
  static async grantPermission(req, res, next) {
    try {
      const {
        userId,
        resourceName,
        permissions,
        subaccountId = null,
        expiresAt = null,
        constraints = {}
      } = req.body;

      const grantedBy = req.user.id;

      Logger.audit('Grant permission', 'rbac', {
        grantedBy,
        targetUserId: userId,
        resourceName,
        permissions,
        subaccountId
      });

      // Validate target user exists
      const targetUser = await User.findById(userId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'Target user not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Grant permission
      const result = await Permission.grantPermission({
        userId,
        resourceName,
        permissions,
        subaccountId,
        grantedBy,
        expiresAt,
        constraints
      });

      if (!result.success) {
        return res.status(400).json({
          success: false,
          message: result.error,
          code: 'PERMISSION_GRANT_FAILED'
        });
      }

      Logger.security('Permission granted', 'medium', {
        grantedBy,
        targetUserId: userId,
        targetUserEmail: targetUser.email,
        resourceName,
        permissions,
        subaccountId,
        permissionId: result.permission._id
      });

      res.json({
        success: true,
        message: 'Permission granted successfully',
        data: result.permission
      });

    } catch (error) {
      Logger.error('Failed to grant permission', {
        error: error.message,
        grantedBy: req.user?.id,
        requestData: req.body
      });
      next(error);
    }
  }

  // Revoke permission from user
  static async revokePermission(req, res, next) {
    try {
      const { userId, resourceName, subaccountId = null } = req.body;
      const revokedBy = req.user.id;

      Logger.audit('Revoke permission', 'rbac', {
        revokedBy,
        targetUserId: userId,
        resourceName,
        subaccountId
      });

      const result = await Permission.revokePermission(userId, resourceName, subaccountId);

      if (!result.success) {
        return res.status(400).json({
          success: false,
          message: result.error,
          code: 'PERMISSION_REVOKE_FAILED'
        });
      }

      Logger.security('Permission revoked', 'medium', {
        revokedBy,
        targetUserId: userId,
        resourceName,
        subaccountId,
        revoked: result.revoked
      });

      res.json({
        success: true,
        message: result.revoked ? 'Permission revoked successfully' : 'Permission not found',
        data: { revoked: result.revoked }
      });

    } catch (error) {
      Logger.error('Failed to revoke permission', {
        error: error.message,
        revokedBy: req.user?.id,
        requestData: req.body
      });
      next(error);
    }
  }

  // Check user permissions for a resource
  static async checkUserPermissions(req, res, next) {
    try {
      const { userId, resourceName, subaccountId = null } = req.query;

      if (!userId || !resourceName) {
        return res.status(400).json({
          success: false,
          message: 'userId and resourceName are required',
          code: 'MISSING_PARAMETERS'
        });
      }

      // Check all permissions for the resource
      const permissions = ['read', 'write', 'delete', 'admin'];
      const results = {};

      for (const permission of permissions) {
        const result = await Permission.checkPermission(userId, resourceName, permission, subaccountId);
        results[permission] = {
          hasPermission: result.hasPermission,
          reason: result.reason,
          effectiveRole: result.effectiveRole
        };
      }

      res.json({
        success: true,
        data: {
          userId,
          resourceName,
          subaccountId,
          permissions: results
        }
      });

    } catch (error) {
      Logger.error('Failed to check user permissions', {
        error: error.message,
        userId: req.user?.id,
        queryData: req.query
      });
      next(error);
    }
  }

  // List user's permissions
  static async listUserPermissions(req, res, next) {
    try {
      const { userId } = req.params;
      const { subaccountId, resourceType, isActive = true } = req.query;

      const query = { userId, isActive };
      if (subaccountId) query.subaccountId = subaccountId;

      let permissions = await Permission.find(query)
        .populate('resourceId', 'name description type service')
        .populate('subaccountId', 'name description')
        .populate('grantedBy', 'email firstName lastName')
        .sort({ createdAt: -1 });

      // Filter by resource type if specified
      if (resourceType) {
        permissions = permissions.filter(p => p.resourceId.type === resourceType);
      }

      res.json({
        success: true,
        data: {
          userId,
          permissions,
          count: permissions.length
        }
      });

    } catch (error) {
      Logger.error('Failed to list user permissions', {
        error: error.message,
        userId: req.user?.id,
        targetUserId: req.params.userId
      });
      next(error);
    }
  }

  // Get RBAC system overview
  static async getRBACOverview(req, res, next) {
    try {
      const [
        resourceCount,
        permissionCount,
        activePermissionCount,
        resourcesByService,
        permissionsByRole
      ] = await Promise.all([
        Resource.countDocuments({ isActive: true }),
        Permission.countDocuments({}),
        Permission.countDocuments({ isActive: true }),
        Resource.aggregate([
          { $match: { isActive: true } },
          { $group: { _id: '$service', count: { $sum: 1 } } }
        ]),
        Permission.aggregate([
          { $match: { isActive: true } },
          { $group: { _id: '$compositeRole.effectiveRole', count: { $sum: 1 } } }
        ])
      ]);

      res.json({
        success: true,
        data: {
          overview: {
            totalResources: resourceCount,
            totalPermissions: permissionCount,
            activePermissions: activePermissionCount
          },
          resourcesByService: resourcesByService.reduce((acc, item) => {
            acc[item._id] = item.count;
            return acc;
          }, {}),
          permissionsByRole: permissionsByRole.reduce((acc, item) => {
            acc[item._id] = item.count;
            return acc;
          }, {})
        }
      });

    } catch (error) {
      Logger.error('Failed to get RBAC overview', {
        error: error.message,
        userId: req.user?.id
      });
      next(error);
    }
  }
}

module.exports = RBACController; 