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
  logoutAll
} = require('../controllers/authController');

// Import validators
const {
  validateRegister,
  validateLogin,
  validateResetPasswordRequest,
  validateResetPassword,
  validateRefreshToken
} = require('../validators/authValidator');

// Import middleware
const { authenticateToken } = require('../middleware/authMiddleware');

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

module.exports = router;
