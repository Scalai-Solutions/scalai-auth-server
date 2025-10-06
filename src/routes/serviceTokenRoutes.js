const express = require('express');
const router = express.Router();
const {
  createServiceToken,
  getServiceTokens,
  getServiceToken,
  updateServiceToken,
  regenerateServiceToken,
  deleteServiceToken
} = require('../controllers/serviceTokenController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requirePermission } = require('../middleware/rbacMiddleware');

// All service token routes require authentication and admin permissions
router.use(authenticateToken);
router.use(requirePermission('service_tokens', 'manage'));

// Create a new service token
router.post('/', createServiceToken);

// Get all service tokens
router.get('/', getServiceTokens);

// Get a specific service token
router.get('/:serviceName', getServiceToken);

// Update a service token
router.put('/:serviceName', updateServiceToken);

// Regenerate a service token
router.post('/:serviceName/regenerate', regenerateServiceToken);

// Delete a service token
router.delete('/:serviceName', deleteServiceToken);

module.exports = router; 