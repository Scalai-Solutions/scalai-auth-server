const Resource = require('../models/Resource');
const Permission = require('../models/Permission');
const User = require('../models/User');
const Subaccount = require('../models/Subaccount');
const Logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');
const { cacheInvalidationService } = require('../utils/cacheInvalidation');
const { invalidateDatabaseServerCacheBulk } = require('../utils/cacheInvalidationHelper');
const axios = require('axios');
const config = require('../../config/config');

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

      // Invalidate resource cache since a new resource was created
      try {
        await cacheInvalidationService.invalidateResource(
          resource.name, 
          'resource_created'
        );
      } catch (cacheError) {
        Logger.warn('Cache invalidation failed after resource creation', {
          error: cacheError.message,
          resourceName: resource.name
        });
      }

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

  // Update an existing resource
  static async updateResource(req, res, next) {
    try {
      const { resourceId } = req.params;
      const {
        description,
        endpoints,
        defaultPermissions,
        settings,
        isActive
      } = req.body;

      const updatedBy = req.user.id;

      Logger.audit('Update resource', 'rbac', {
        userId: updatedBy,
        resourceId,
        updateFields: Object.keys(req.body)
      });

      // Find the resource
      const resource = await Resource.findById(resourceId);
      if (!resource) {
        return res.status(404).json({
          success: false,
          message: 'Resource not found',
          code: 'RESOURCE_NOT_FOUND'
        });
      }

      // Update fields if provided
      if (description !== undefined) {
        resource.description = description;
      }

      if (endpoints !== undefined) {
        // Merge new endpoints with existing ones, avoiding duplicates
        const existingEndpoints = resource.endpoints || [];
        const newEndpoints = endpoints;
        
        // Create a map of existing endpoints by method+path for quick lookup
        const endpointMap = new Map();
        existingEndpoints.forEach(ep => {
          const key = `${ep.method}:${ep.path}`;
          endpointMap.set(key, ep);
        });
        
        // Add or update endpoints
        newEndpoints.forEach(newEp => {
          const key = `${newEp.method}:${newEp.path}`;
          endpointMap.set(key, newEp); // This will update if exists, add if new
        });
        
        // Convert map back to array
        resource.endpoints = Array.from(endpointMap.values());
        
        Logger.info('Endpoints merged', {
          resourceId: resource._id,
          previousCount: existingEndpoints.length,
          newCount: resource.endpoints.length,
          addedOrUpdated: newEndpoints.length
        });
      }

      if (defaultPermissions !== undefined) {
        resource.defaultPermissions = {
          ...resource.defaultPermissions,
          ...defaultPermissions
        };
      }

      if (settings !== undefined) {
        resource.settings = {
          ...resource.settings,
          ...settings
        };
      }

      if (isActive !== undefined) {
        resource.isActive = isActive;
      }

      await resource.save();

      Logger.info('Resource updated successfully', {
        resourceId: resource._id,
        name: resource.name,
        updatedBy,
        updatedFields: Object.keys(req.body)
      });

      // Invalidate resource cache
      try {
        await cacheInvalidationService.invalidateResource(
          resource.name,
          'resource_updated'
        );
      } catch (cacheError) {
        Logger.warn('Cache invalidation failed after resource update', {
          error: cacheError.message,
          resourceName: resource.name
        });
      }

      res.json({
        success: true,
        message: 'Resource updated successfully',
        data: resource
      });

    } catch (error) {
      Logger.error('Failed to update resource', {
        error: error.message,
        userId: req.user?.id,
        resourceId: req.params.resourceId,
        updateData: req.body
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

      // Invalidate cache for the user whose permissions changed
      try {
        await cacheInvalidationService.invalidateUserPermissions(
          userId, 
          subaccountId, 
          'permission_granted'
        );
      } catch (cacheError) {
        Logger.warn('Cache invalidation failed after permission grant', {
          error: cacheError.message,
          userId,
          subaccountId,
          resourceName
        });
      }

      // Invalidate database server cache
      const { invalidateDatabaseServerCache } = require('../utils/cacheInvalidationHelper');
      await invalidateDatabaseServerCache(userId, subaccountId);

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

      // Invalidate cache for the user whose permissions changed
      if (result.revoked) {
        try {
          await cacheInvalidationService.invalidateUserPermissions(
            userId, 
            subaccountId, 
            'permission_revoked'
          );
        } catch (cacheError) {
          Logger.warn('Cache invalidation failed after permission revoke', {
            error: cacheError.message,
            userId,
            subaccountId,
            resourceName
          });
        }

        // Invalidate database server cache
        const { invalidateDatabaseServerCache } = require('../utils/cacheInvalidationHelper');
        await invalidateDatabaseServerCache(userId, subaccountId);
      }

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

  // Resolve resource and required permissions by endpoint
  static async resolveResourceByEndpoint(req, res, next) {
    try {
      const { method, path, service } = req.query;

      if (!method || !path || !service) {
        return res.status(400).json({
          success: false,
          message: 'method, path, and service are required',
          code: 'MISSING_PARAMETERS'
        });
      }

      // Find resource by endpoint
      const resource = await Resource.findByEndpoint(method, path, service);
      
      if (!resource) {
        return res.status(404).json({
          success: false,
          message: 'No resource found for this endpoint',
          code: 'RESOURCE_NOT_FOUND',
          data: {
            method,
            path,
            service
          }
        });
      }

      // Get required permissions from resource definition
      const requiredPermissions = resource.getRequiredPermissions(method, path);

      res.json({
        success: true,
        data: {
          resourceName: resource.name,
          resourceId: resource._id,
          resourceType: resource.type,
          requiredPermissions,
          endpoint: {
            method,
            path,
            service
          },
          settings: resource.settings
        }
      });

    } catch (error) {
      Logger.error('Failed to resolve resource by endpoint', {
        error: error.message,
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

  // Get subaccount permissions (based on first non-owner user)
  static async getSubaccountPermissions(req, res, next) {
    try {
      const { subaccountId } = req.params;
      const { resourceType, isActive = true } = req.query;
      const requesterId = req.user?.id || req.service?.userId || 'service';

      // TODO: Implement Redis caching when Redis is available
      // const cacheKey = `subaccount_permissions:${subaccountId}:${resourceType || 'all'}:${isActive}`;

      Logger.debug('Subaccount permissions request', {
        subaccountId,
        requesterId,
        resourceType
      });

      // Get all users of the subaccount from tenant-manager service
      let subaccountUsers;
      try {
        const tenantManagerUrl = config.services.tenantManagerUrl;
        const serviceToken = config.serviceTokens.tenantManager;
        const userId = req.user?.id || requesterId;
        
        const response = await axios.get(
          `${tenantManagerUrl}/api/subaccounts/${subaccountId}/users`,
          {
            headers: {
              'X-Service-Token': serviceToken,
              'X-User-ID': userId,
              'X-Service-Name': 'auth-server'
            }
          }
        );

        if (!response.data.success || !response.data.data.users) {
          Logger.error('Failed to fetch users from tenant-manager', {
            subaccountId,
            response: response.data
          });
          return res.status(500).json({
            success: false,
            message: 'Failed to fetch subaccount users',
            code: 'FETCH_USERS_FAILED'
          });
        }

        subaccountUsers = response.data.data.users;
      } catch (error) {
        Logger.error('Error calling tenant-manager service', {
          error: error.message,
          subaccountId,
          url: `${config.services.tenantManagerUrl}/api/subaccounts/${subaccountId}/users`
        });
        return res.status(500).json({
          success: false,
          message: 'Failed to communicate with tenant-manager service',
          code: 'SERVICE_COMMUNICATION_ERROR'
        });
      }

      if (subaccountUsers.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No users found for this subaccount',
          code: 'NO_USERS_FOUND'
        });
      }

      // Find first non-owner user
      const targetUser = subaccountUsers.find(user => user.role !== 'owner');
      
      if (!targetUser) {
        // If all users are owners, use the first user
        Logger.debug('All users are owners, using first user', {
          subaccountId,
          userId: subaccountUsers[0].id
        });
        const firstUser = subaccountUsers[0];
        
        const query = { userId: firstUser.id, isActive, subaccountId };
        let permissions = await Permission.find(query)
          .populate('resourceId', 'name description type service')
          .populate('subaccountId', 'name description')
          .populate('grantedBy', 'email firstName lastName')
          .sort({ createdAt: -1 });

        if (resourceType) {
          permissions = permissions.filter(p => p.resourceId.type === resourceType);
        }

        return res.json({
          success: true,
          data: {
            subaccountId,
            representativeUser: {
              id: firstUser.id,
              email: firstUser.email,
              role: firstUser.role,
              note: 'All users are owners'
            },
            permissions,
            count: permissions.length
          }
        });
      }

      // Get permissions for the non-owner user
      const query = { userId: targetUser.id, isActive, subaccountId };
      let permissions = await Permission.find(query)
        .populate('resourceId', 'name description type service')
        .populate('subaccountId', 'name description')
        .populate('grantedBy', 'email firstName lastName')
        .sort({ createdAt: -1 });

      // Filter by resource type if specified
      if (resourceType) {
        permissions = permissions.filter(p => p.resourceId.type === resourceType);
      }

      Logger.audit('Subaccount permissions retrieved', 'subaccount_permissions', {
        subaccountId,
        representativeUserId: targetUser.id,
        permissionCount: permissions.length,
        requesterId
      });

      res.json({
        success: true,
        data: {
          subaccountId,
          representativeUser: {
            id: targetUser.id,
            email: targetUser.email,
            role: targetUser.role
          },
          permissions,
          count: permissions.length
        }
      });

    } catch (error) {
      Logger.error('Failed to get subaccount permissions', {
        error: error.message,
        subaccountId: req.params.subaccountId,
        requesterId: req.user?.id
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

  // Enable resource permissions for all users of a subaccount
  static async enableResourcePermissionsForSubaccount(req, res, next) {
    try {
      const { subaccountId, resourceName } = req.params;
      const { permissions } = req.body;
      const grantedBy = req.user?.id || req.headers['x-user-id'];

      // Validate permissions - admin should always be false
      if (!permissions || typeof permissions !== 'object') {
        return res.status(400).json({
          success: false,
          message: 'Permissions object is required',
          code: 'INVALID_PERMISSIONS'
        });
      }

      // Force admin to false
      const validPermissions = {
        read: permissions.read === true,
        write: permissions.write === true,
        delete: permissions.delete === true,
        admin: false
      };

      Logger.audit('Enable resource permissions for subaccount', 'rbac', {
        grantedBy,
        subaccountId,
        resourceName,
        permissions: validPermissions
      });

      // // Validate subaccount exists
      // const subaccount = await Subaccount.findById(subaccountId);
      // if (!subaccount) {
      //   return res.status(404).json({
      //     success: false,
      //     message: 'Subaccount not found',
      //     code: 'SUBACCOUNT_NOT_FOUND'
      //   });
      // }

      // Validate resource exists
      const resource = await Resource.findOne({ name: resourceName, isActive: true });
      if (!resource) {
        return res.status(404).json({
          success: false,
          message: 'Resource not found',
          code: 'RESOURCE_NOT_FOUND'
        });
      }

      // Get all users of the subaccount from tenant-manager service
      let subaccountUsers;
      try {
        const tenantManagerUrl = config.services.tenantManagerUrl;
        const serviceToken = config.serviceTokens.tenantManager;
        const userId = req.user?.id || grantedBy;
        
        const response = await axios.get(
          `${tenantManagerUrl}/api/subaccounts/${subaccountId}/users`,
          {
            headers: {
              'Authorization': `${req.headers.authorization}`,
              'X-Service-Token': serviceToken,
              'X-User-ID': userId,
              'X-Service-Name': 'auth-server'
            }
          }
        );

        if (!response.data.success || !response.data.data.users) {
          Logger.error('Failed to fetch users from tenant-manager', {
            subaccountId,
            response: response.data
          });
          return res.status(500).json({
            success: false,
            message: 'Failed to fetch subaccount users',
            code: 'FETCH_USERS_FAILED'
          });
        }

        subaccountUsers = response.data.data.users.filter(user => user.role !== 'owner');
      } catch (error) {
        Logger.error('Error calling tenant-manager service', {
          error: error.message,
          subaccountId,
          url: `${config.services.tenantManagerUrl}/api/subaccounts/${subaccountId}/users`
        });
        return res.status(500).json({
          success: false,
          message: 'Failed to communicate with tenant-manager service',
          code: 'SERVICE_COMMUNICATION_ERROR'
        });
      }

      if (subaccountUsers.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No users found for this subaccount',
          code: 'NO_USERS_FOUND'
        });
      }

      // Grant permissions to all users
      const results = [];
      const errors = [];

      for (const user of subaccountUsers) {
        try {
          const result = await Permission.grantPermission({
            userId: user.id,
            resourceName,
            permissions: validPermissions,
            subaccountId,
            grantedBy
          });

          if (result.success) {
            results.push({
              userId: user.id,
              userEmail: user.email,
              success: true,
              permissionId: result.permission._id
            });

            // Invalidate cache for this user
            try {
              await cacheInvalidationService.invalidateUserPermissions(
                user.id,
                subaccountId,
                'bulk_permission_grant'
              );
            } catch (cacheError) {
              Logger.warn('Cache invalidation failed', {
                error: cacheError.message,
                userId: user.id
              });
            }
          } else {
            errors.push({
              userId: user.id,
              userEmail: user.email,
              error: result.error
            });
          }
        } catch (error) {
          errors.push({
            userId: user.id,
            userEmail: user.email,
            error: error.message
          });
        }
      }

      Logger.security('Bulk permissions granted for resource', 'high', {
        grantedBy,
        subaccountId,
        resourceName,
        totalUsers: subaccountUsers.length,
        successCount: results.length,
        errorCount: errors.length
      });

      // Invalidate database server cache for all affected users
      const userIds = subaccountUsers.map(user => user.id);
      await invalidateDatabaseServerCacheBulk(userIds, subaccountId);

      res.json({
        success: true,
        message: `Permissions granted to ${results.length} users`,
        data: {
          subaccountId,
          resourceName,
          permissions: validPermissions,
          totalUsers: subaccountUsers.length,
          successCount: results.length,
          errorCount: errors.length,
          results,
          errors: errors.length > 0 ? errors : undefined
        }
      });

    } catch (error) {
      Logger.error('Failed to enable resource permissions for subaccount', {
        error: error.message,
        grantedBy: req.user?.id || req.headers['x-user-id'],
        subaccountId: req.params.subaccountId,
        resourceName: req.params.resourceName
      });
      next(error);
    }
  }

  // Enable permissions for all resources for all users of a subaccount
  static async enableAllResourcePermissionsForSubaccount(req, res, next) {
    try {
      const { subaccountId } = req.params;
      const { permissions } = req.body;
      const grantedBy = req.user?.id || req.headers['x-user-id'];

      // Validate permissions - admin should always be false
      if (!permissions || typeof permissions !== 'object') {
        return res.status(400).json({
          success: false,
          message: 'Permissions object is required',
          code: 'INVALID_PERMISSIONS'
        });
      }

      // Force admin to false
      const validPermissions = {
        read: permissions.read === true,
        write: permissions.write === true,
        delete: permissions.delete === true,
        admin: false
      };

      Logger.audit('Enable all resource permissions for subaccount', 'rbac', {
        grantedBy,
        subaccountId,
        permissions: validPermissions
      });

      // // Validate subaccount exists
      // const subaccount = await Subaccount.findById(subaccountId);
      // if (!subaccount) {
      //   return res.status(404).json({
      //     success: false,
      //     message: 'Subaccount not found',
      //     code: 'SUBACCOUNT_NOT_FOUND'
      //   });
      // }

      // Get all active resources
      const resources = await Resource.find({ isActive: true });
      if (resources.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No active resources found',
          code: 'NO_RESOURCES_FOUND'
        });
      }

      // Get all users of the subaccount from tenant-manager service
      let subaccountUsers;
      try {
        const tenantManagerUrl = config.services.tenantManagerUrl;
        const serviceToken = config.serviceTokens.tenantManager;
        const userId = req.user?.id || grantedBy;
        
        const response = await axios.get(
          `${tenantManagerUrl}/api/subaccounts/${subaccountId}/users`,
          {
            headers: {
              'X-Service-Token': serviceToken,
              'X-User-ID': userId,
              'X-Service-Name': 'auth-server'
            }
          }
        );

        if (!response.data.success || !response.data.data.users) {
          Logger.error('Failed to fetch users from tenant-manager', {
            subaccountId,
            response: response.data
          });
          return res.status(500).json({
            success: false,
            message: 'Failed to fetch subaccount users',
            code: 'FETCH_USERS_FAILED'
          });
        }

        subaccountUsers = response.data.data.users.filter(user => user.role !== 'owner');
      } catch (error) {
        Logger.error('Error calling tenant-manager service', {
          error: error.message,
          subaccountId,
          url: `${config.services.tenantManagerUrl}/api/subaccounts/${subaccountId}/users`
        });
        return res.status(500).json({
          success: false,
          message: 'Failed to communicate with tenant-manager service',
          code: 'SERVICE_COMMUNICATION_ERROR'
        });
      }

      if (subaccountUsers.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No users found for this subaccount',
          code: 'NO_USERS_FOUND'
        });
      }

      // Grant permissions to all users for all resources
      const results = [];
      const errors = [];
      let totalOperations = 0;

      for (const resource of resources) {
        for (const user of subaccountUsers) {
          totalOperations++;
          try {
            const result = await Permission.grantPermission({
              userId: user.id,
              resourceName: resource.name,
              permissions: validPermissions,
              subaccountId,
              grantedBy
            });

            if (result.success) {
              results.push({
                userId: user.id,
                userEmail: user.email,
                resourceName: resource.name,
                success: true,
                permissionId: result.permission._id
              });
            } else {
              errors.push({
                userId: user.id,
                userEmail: user.email,
                resourceName: resource.name,
                error: result.error
              });
            }
          } catch (error) {
            errors.push({
              userId: user.id,
              userEmail: user.email,
              resourceName: resource.name,
              error: error.message
            });
          }
        }
      }

      // Invalidate cache for all users
      for (const user of subaccountUsers) {
        try {
          await cacheInvalidationService.invalidateUserPermissions(
            user.id,
            subaccountId,
            'bulk_all_permission_grant'
          );
        } catch (cacheError) {
          Logger.warn('Cache invalidation failed', {
            error: cacheError.message,
            userId: user.id
          });
        }
      }

      Logger.security('Bulk permissions granted for all resources', 'critical', {
        grantedBy,
        subaccountId,
        totalUsers: subaccountUsers.length,
        totalResources: resources.length,
        totalOperations,
        successCount: results.length,
        errorCount: errors.length
      });

      // Invalidate database server cache for all affected users
      const userIds = subaccountUsers.map(user => user.id);
      await invalidateDatabaseServerCacheBulk(userIds, subaccountId);

      res.json({
        success: true,
        message: `Permissions granted to ${subaccountUsers.length} users for ${resources.length} resources`,
        data: {
          subaccountId,
          permissions: validPermissions,
          totalUsers: subaccountUsers.length,
          totalResources: resources.length,
          totalOperations,
          successCount: results.length,
          errorCount: errors.length,
          resourcesProcessed: resources.map(r => r.name),
          errors: errors.length > 0 ? errors : undefined
        }
      });

    } catch (error) {
      Logger.error('Failed to enable all resource permissions for subaccount', {
        error: error.message,
        grantedBy: req.user?.id || req.headers['x-user-id'],
        subaccountId: req.params.subaccountId
      });
      next(error);
    }
  }
}

module.exports = RBACController; 