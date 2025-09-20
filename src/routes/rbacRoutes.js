const express = require('express');
const router = express.Router();

// Import controllers
const RBACController = require('../controllers/rbacController');

// Import middleware
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireRole } = require('../middleware/rbacMiddleware');
const { 
  requireAuthorizedIP, 
  requireSuperAdmin, 
  logSensitiveOperation 
} = require('../middleware/ipAuthMiddleware');

// Apply authentication to all RBAC routes
router.use(authenticateToken);

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
  requireRole('admin'),
  RBACController.checkUserPermissions
);

router.get('/permissions/user/:userId',
  requireRole('admin'),
  RBACController.listUserPermissions
);

// System overview (Admin and above)
router.get('/overview',
  requireRole('admin'),
  RBACController.getRBACOverview
);

module.exports = router; 