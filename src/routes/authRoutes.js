const express = require('express');
const router = express.Router();

// Import controllers
const {
  register,
  login,
  requestPasswordReset,
  resetPassword,
  refreshToken,
  getProfile,
  getActiveSessions,
  revokeSession,
  logout,
  logoutAll,
  changeUserRole
} = require('../controllers/authController');

// Import validators
const {
  validateRegister,
  validateLogin,
  validateResetPasswordRequest,
  validateResetPassword,
  validateRefreshToken,
  validateChangeUserRole
} = require('../validators/authValidator');

// Import middleware
const { authenticateToken } = require('../middleware/authMiddleware');
const { 
  requireAuthorizedIP, 
  requireSuperAdmin, 
  logSensitiveOperation 
} = require('../middleware/ipAuthMiddleware');

// Public routes
router.post('/register', validateRegister, register);
router.post('/login', validateLogin, login);
router.post('/request-reset-password', validateResetPasswordRequest, requestPasswordReset);
router.post('/reset-password', validateResetPassword, resetPassword);
router.post('/refresh-token', validateRefreshToken, refreshToken);

// Protected routes
router.get('/profile', authenticateToken, getProfile);
router.get('/sessions', authenticateToken, getActiveSessions);
router.delete('/sessions/:sessionId', authenticateToken, revokeSession);
router.post('/logout', logout); // Can work with or without authentication
router.post('/logout-all', authenticateToken, logoutAll);

// Secure administrative routes (IP-restricted)
router.post('/admin/change-user-role',
  validateChangeUserRole,                        // Validate request body
  authenticateToken,                              // Must be authenticated
  requireSuperAdmin,                             // Must be super admin
  requireAuthorizedIP('changeUserRole'),         // Must be from authorized IP
  logSensitiveOperation('change_user_role'),     // Log the operation
  changeUserRole                                 // Controller method
);

module.exports = router;
