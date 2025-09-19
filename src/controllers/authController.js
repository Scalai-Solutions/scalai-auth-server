const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateTokens, verifyRefreshToken, revokeRefreshToken } = require('../middleware/authMiddleware');
const Logger = require('../utils/logger');

// Helper function to get client info
const getClientInfo = (req) => {
  return {
    ipAddress: req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
               (req.connection.socket ? req.connection.socket.remoteAddress : null),
    userAgent: req.get('User-Agent') || 'Unknown',
    forwardedFor: req.get('X-Forwarded-For'),
    realIP: req.get('X-Real-IP')
  };
};

// Helper function to detect suspicious activity
const detectSuspiciousActivity = async (userId, currentIP, currentUserAgent) => {
  try {
    // Get recent tokens from the last 24 hours
    const recentTokens = await RefreshToken.find({
      user: userId,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      isRevoked: false
    }).sort({ createdAt: -1 }).limit(10);

    const suspiciousFlags = [];

    // Check for IP changes
    const uniqueIPs = [...new Set(recentTokens.map(t => t.ipAddress))];
    if (uniqueIPs.length > 3) {
      suspiciousFlags.push('multiple_ips');
    }

    // Check for new IP
    const knownIPs = recentTokens.map(t => t.ipAddress);
    if (!knownIPs.includes(currentIP) && knownIPs.length > 0) {
      suspiciousFlags.push('new_ip');
    }

    // Check for user agent changes
    const uniqueUserAgents = [...new Set(recentTokens.map(t => t.userAgent))];
    if (uniqueUserAgents.length > 2) {
      suspiciousFlags.push('multiple_user_agents');
    }

    // Check for rapid location changes (basic IP-based detection)
    const lastToken = recentTokens[0];
    if (lastToken && lastToken.ipAddress !== currentIP) {
      const timeDiff = Date.now() - new Date(lastToken.createdAt).getTime();
      if (timeDiff < 30 * 60 * 1000) { // 30 minutes
        suspiciousFlags.push('rapid_location_change');
      }
    }

    return {
      isSuspicious: suspiciousFlags.length > 0,
      flags: suspiciousFlags,
      riskLevel: suspiciousFlags.length >= 2 ? 'high' : suspiciousFlags.length === 1 ? 'medium' : 'low'
    };
  } catch (error) {
    Logger.error('Error detecting suspicious activity', { error: error.message, userId });
    return { isSuspicious: false, flags: [], riskLevel: 'low' };
  }
};

// Helper function to handle security alerts
const handleSecurityAlert = async (user, alertType, clientInfo, suspiciousActivity) => {
  const alertData = {
    userId: user._id,
    email: user.email,
    alertType,
    clientInfo,
    suspiciousActivity,
    timestamp: new Date()
  };

  Logger.warn('Security Alert', alertData);

  // In production, you might want to:
  // 1. Send email notifications
  // 2. Store in a security events collection
  // 3. Integrate with security monitoring tools
  // 4. Implement rate limiting or temporary locks

  if (suspiciousActivity.riskLevel === 'high') {
    Logger.error('High risk security event detected', alertData);
    // Could implement additional measures like temporary account lock
  }
};

// Register user
const register = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const clientInfo = getClientInfo(req);

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      Logger.warn('Registration attempt for existing user', { 
        email, 
        clientInfo: clientInfo.ipAddress 
      });
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Create user
    const user = new User({
      email,
      password,
      firstName,
      lastName
    });

    await user.save();

    Logger.info('New user registered', { 
      userId: user._id, 
      email: user.email,
      ipAddress: clientInfo.ipAddress
    });

    // Generate tokens
    const { accessToken, refreshToken } = await generateTokens(
      user, 
      clientInfo.userAgent, 
      clientInfo.ipAddress
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.toJSON(),
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }
    next(error);
  }
};

// Login user
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const clientInfo = getClientInfo(req);

    // Authenticate user
    const authResult = await User.authenticate(email, password);
    
    if (!authResult.success) {
      Logger.warn('Failed login attempt', { 
        email, 
        reason: authResult.message,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent
      });
      
      return res.status(401).json({
        success: false,
        message: authResult.message
      });
    }

    const { user } = authResult;

    // Detect suspicious activity
    const suspiciousActivity = await detectSuspiciousActivity(
      user._id, 
      clientInfo.ipAddress, 
      clientInfo.userAgent
    );

    // Handle security alerts
    if (suspiciousActivity.isSuspicious) {
      await handleSecurityAlert(user, 'suspicious_login', clientInfo, suspiciousActivity);
      
      // For high-risk logins, you might want to require additional verification
      if (suspiciousActivity.riskLevel === 'high') {
        Logger.error('High-risk login detected', {
          userId: user._id,
          email: user.email,
          suspiciousActivity,
          clientInfo
        });
        
        // Optional: Require email verification for high-risk logins
        // return res.status(200).json({
        //   success: true,
        //   requiresVerification: true,
        //   message: 'Please check your email for verification code'
        // });
      }
    }

    Logger.info('User logged in', { 
      userId: user._id, 
      email: user.email,
      ipAddress: clientInfo.ipAddress,
      riskLevel: suspiciousActivity.riskLevel
    });

    // Generate tokens
    const { accessToken, refreshToken } = await generateTokens(
      user, 
      clientInfo.userAgent, 
      clientInfo.ipAddress
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        accessToken,
        refreshToken,
        // Include security info for client awareness
        securityInfo: {
          riskLevel: suspiciousActivity.riskLevel,
          newDevice: suspiciousActivity.flags.includes('new_ip'),
          flags: suspiciousActivity.flags
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Request password reset
const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.body;
    const clientInfo = getClientInfo(req);

    // Find user by email
    const user = await User.findOne({ email, isActive: true });
    
    if (!user) {
      Logger.warn('Password reset requested for non-existent user', { 
        email, 
        ipAddress: clientInfo.ipAddress 
      });
      // Don't reveal if user exists or not
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent'
      });
    }

    // Generate reset token
    const resetToken = user.generateResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    Logger.info('Password reset requested', { 
      userId: user._id, 
      email: user.email,
      ipAddress: clientInfo.ipAddress
    });

    // In production, send email with reset token
    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent',
      // Remove this in production - only for testing
      ...(process.env.NODE_ENV === 'development' && { resetToken })
    });
  } catch (error) {
    next(error);
  }
};

// Reset password
const resetPassword = async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const clientInfo = getClientInfo(req);

    // Find user by reset token
    const user = await User.findByResetToken(token);
    
    if (!user) {
      Logger.warn('Invalid password reset attempt', { 
        token: token.substring(0, 8) + '...',
        ipAddress: clientInfo.ipAddress 
      });
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    // Update password and clear reset token
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    // Revoke all existing refresh tokens for security
    await RefreshToken.revokeAllUserTokens(user._id);

    Logger.info('Password reset completed', { 
      userId: user._id, 
      email: user.email,
      ipAddress: clientInfo.ipAddress
    });

    // Security alert for password reset
    await handleSecurityAlert(user, 'password_reset', clientInfo, { riskLevel: 'medium' });

    res.json({
      success: true,
      message: 'Password reset successful'
    });
  } catch (error) {
    next(error);
  }
};

// Refresh token
const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;
    const clientInfo = getClientInfo(req);

    // Verify refresh token
    const tokenResult = await verifyRefreshToken(token);
    const { user, tokenId } = tokenResult;

    // Get the stored token to check IP
    const storedToken = await RefreshToken.findOne({ token: tokenId });
    
    if (storedToken) {
      // Check for IP mismatch
      if (storedToken.ipAddress !== clientInfo.ipAddress) {
        Logger.warn('Refresh token used from different IP', {
          userId: user._id,
          email: user.email,
          originalIP: storedToken.ipAddress,
          currentIP: clientInfo.ipAddress
        });

        // Security alert for IP mismatch
        await handleSecurityAlert(user, 'token_ip_mismatch', clientInfo, { 
          riskLevel: 'high',
          originalIP: storedToken.ipAddress 
        });

        // Optional: Revoke token for security
        await revokeRefreshToken(tokenId);
        
        return res.status(401).json({
          success: false,
          message: 'Token security validation failed. Please login again.'
        });
      }
    }

    // Revoke the used refresh token
    await revokeRefreshToken(tokenId);

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = await generateTokens(
      user, 
      clientInfo.userAgent, 
      clientInfo.ipAddress
    );

    Logger.info('Token refreshed', { 
      userId: user._id, 
      email: user.email,
      ipAddress: clientInfo.ipAddress
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    Logger.warn('Token refresh failed', { 
      error: error.message,
      ipAddress: getClientInfo(req).ipAddress
    });
    
    return res.status(401).json({
      success: false,
      message: error.message
    });
  }
};

// Get current user profile
const getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile retrieved successfully',
      data: {
        user: user.toJSON()
      }
    });
  } catch (error) {
    next(error);
  }
};

// Get user's active sessions
const getActiveSessions = async (req, res, next) => {
  try {
    const sessions = await RefreshToken.find({
      user: req.user.id,
      isRevoked: false,
      expiresAt: { $gt: new Date() }
    }).select('ipAddress userAgent createdAt').sort({ createdAt: -1 });

    res.json({
      success: true,
      message: 'Active sessions retrieved successfully',
      data: {
        sessions: sessions.map(session => ({
          id: session._id,
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          createdAt: session.createdAt,
          isCurrent: session.ipAddress === getClientInfo(req).ipAddress
        }))
      }
    });
  } catch (error) {
    next(error);
  }
};

// Revoke specific session
const revokeSession = async (req, res, next) => {
  try {
    const { sessionId } = req.params;
    const clientInfo = getClientInfo(req);

    const session = await RefreshToken.findOne({
      _id: sessionId,
      user: req.user.id,
      isRevoked: false
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    await RefreshToken.updateOne(
      { _id: sessionId },
      { $set: { isRevoked: true } }
    );

    Logger.info('Session revoked', {
      userId: req.user.id,
      sessionId,
      revokedFromIP: clientInfo.ipAddress,
      revokedSessionIP: session.ipAddress
    });

    res.json({
      success: true,
      message: 'Session revoked successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Logout (revoke refresh token)
const logout = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;
    const clientInfo = getClientInfo(req);

    if (token) {
      try {
        const decoded = require('jsonwebtoken').verify(token, require('../../config/config').jwt.refreshSecret);
        await revokeRefreshToken(decoded.tokenId);
      } catch (error) {
        // Token might be invalid, but we'll still respond with success
      }
    }

    Logger.info('User logged out', { 
      userId: req.user?.id,
      ipAddress: clientInfo.ipAddress
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Logout from all devices (revoke all refresh tokens)
const logoutAll = async (req, res, next) => {
  try {
    const clientInfo = getClientInfo(req);
    
    await RefreshToken.revokeAllUserTokens(req.user.id);

    Logger.info('User logged out from all devices', { 
      userId: req.user.id,
      ipAddress: clientInfo.ipAddress
    });

    res.json({
      success: true,
      message: 'Logged out from all devices successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Secure operation: Change user role (restricted to authorized IPs)
const changeUserRole = async (req, res, next) => {
  try {
    const { userId, newRole, reason } = req.body;
    const adminUserId = req.user.id;

    // Validate required fields
    if (!userId || !newRole) {
      return res.status(400).json({
        success: false,
        message: 'User ID and new role are required',
        code: 'MISSING_REQUIRED_FIELDS'
      });
    }

    // Validate role
    const validRoles = ['user', 'admin', 'super_admin'];
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role specified',
        code: 'INVALID_ROLE',
        validRoles
      });
    }

    // Find target user
    const targetUser = await User.findById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user is trying to change their own role
    if (userId === adminUserId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot change your own role',
        code: 'CANNOT_CHANGE_OWN_ROLE'
      });
    }

    // Store old role for logging
    const oldRole = targetUser.role;

    // Check if role is actually changing
    if (oldRole === newRole) {
      return res.status(400).json({
        success: false,
        message: 'User already has the specified role',
        code: 'ROLE_UNCHANGED'
      });
    }

    // Additional validation for super_admin role creation
    if (newRole === 'super_admin') {
      // Only existing super_admins can create new super_admins
      if (req.user.role !== 'super_admin') {
        return res.status(403).json({
          success: false,
          message: 'Only super admins can create other super admins',
          code: 'SUPER_ADMIN_CREATION_DENIED'
        });
      }

      // Require reason for super_admin role changes
      if (!reason || reason.trim().length < 10) {
        return res.status(400).json({
          success: false,
          message: 'Detailed reason required for super admin role assignment (minimum 10 characters)',
          code: 'REASON_REQUIRED'
        });
      }
    }

    // Update user role
    targetUser.role = newRole;
    
    // Increment session version to invalidate existing tokens
    targetUser.sessionVersion += 1;
    
    await targetUser.save();

    Logger.security('User role changed', 'critical', {
      adminUserId,
      targetUserId: userId,
      targetUserEmail: targetUser.email,
      oldRole,
      newRole,
      reason: reason || 'No reason provided',
      clientIP: req.authorizedIP?.ipAddress,
      authorizedIPId: req.authorizedIP?.id
    });

    // Log audit entry
    const AuditLog = require('../models/AuditLog');
    await AuditLog.logOperation({
      userId: adminUserId,
      operation: 'change_user_role',
      resource: 'user',
      resourceId: userId,
      details: {
        targetUserEmail: targetUser.email,
        oldRole,
        newRole,
        reason,
        requiresReauthentication: true
      },
      result: { success: true },
      requestContext: {
        ipAddress: req.authorizedIP?.ipAddress,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl
      },
      securityFlags: {
        isSensitiveOperation: true,
        requiresAuthorizedIP: true,
        riskLevel: newRole === 'super_admin' ? 'critical' : 'high'
      }
    });

    res.json({
      success: true,
      message: 'User role changed successfully',
      data: {
        userId: targetUser._id,
        email: targetUser.email,
        oldRole,
        newRole,
        sessionVersionIncremented: true,
        requiresReauthentication: true
      },
      meta: {
        changedBy: adminUserId,
        changedAt: new Date(),
        clientIP: req.authorizedIP?.ipAddress,
        dailyUsageRemaining: req.authorizedIP?.dailyUsageRemaining
      }
    });

  } catch (error) {
    Logger.error('Failed to change user role', {
      error: error.message,
      stack: error.stack,
      adminUserId: req.user?.id,
      targetUserId: req.body?.userId,
      newRole: req.body?.newRole
    });

    next(error);
  }
};

module.exports = {
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
};
