const express = require('express');
const router = express.Router();

// Import controllers
const RBACController = require('../controllers/rbacController');

// Import middleware
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireRole, requireAdminOrSelf } = require('../middleware/rbacMiddleware');
const { 
  requireAuthorizedIP, 
  requireSuperAdmin, 
  logSensitiveOperation 
} = require('../middleware/ipAuthMiddleware');
const { authenticateTokenOrTenantManager } = require('../middleware/serviceAuthMiddleware');

// Apply authentication to all RBAC routes (except bulk permission routes which use custom auth)
router.use((req, res, next) => {
  // Skip default auth for bulk permission routes that use authenticateTokenOrTenantManager
  const path = req.path || req.originalUrl;
  if (path.includes('/subaccounts/') && path.includes('/resources/') && path.includes('/enable-permissions')) {
    return next();
  }
  if (path.includes('/subaccounts/') && path.includes('/enable-all-permissions')) {
    return next();
  }
  return authenticateToken(req, res, next);
});

// Resource management (Super admin only)
router.post('/resources',
  requireSuperAdmin,
  logSensitiveOperation('create_resource'),
  RBACController.createResource
);

router.get('/resources',
  requireRole('admin'),
  RBACController.listResources
);

router.put('/resources/:resourceId',
  requireSuperAdmin,
  logSensitiveOperation('update_resource'),
  RBACController.updateResource
);

// Permission management (Admin and above)
router.post('/permissions/grant',
  requireRole('admin'),
  logSensitiveOperation('grant_permission'),
  RBACController.grantPermission
);

router.post('/permissions/revoke',
  requireRole('admin'),
  logSensitiveOperation('revoke_permission'),
  RBACController.revokePermission
);

router.get('/permissions/check',
  RBACController.checkUserPermissions
);

// Resolve resource by endpoint (for microservices to determine RBAC requirements)
router.get('/resources/resolve',
  RBACController.resolveResourceByEndpoint
);

router.get('/permissions/user/:userId',
  requireAdminOrSelf('userId'),
  RBACController.listUserPermissions
);

// Get subaccount permissions (based on first non-owner user)
router.get('/subaccounts/:subaccountId/permissions',
  requireRole('admin'),
  RBACController.getSubaccountPermissions
);

// System overview (Admin and above)
router.get('/overview',
  requireRole('admin'),
  RBACController.getRBACOverview
);

// Bulk permission operations (Admin and above or Tenant Manager service token)
router.post('/subaccounts/:subaccountId/resources/:resourceName/enable-permissions',
  authenticateTokenOrTenantManager,
  requireRole('admin'),
  logSensitiveOperation('bulk_enable_resource_permissions'),
  RBACController.enableResourcePermissionsForSubaccount
);

router.post('/subaccounts/:subaccountId/enable-all-permissions',
  authenticateTokenOrTenantManager,
  requireRole('admin'),
  logSensitiveOperation('bulk_enable_all_permissions'),
  RBACController.enableAllResourcePermissionsForSubaccount
);

module.exports = router; 