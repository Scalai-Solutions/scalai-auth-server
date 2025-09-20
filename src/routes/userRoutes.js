const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');
const Logger = require('../utils/logger');

// GET /api/users/search - Search for users by email
router.get('/search', authenticateToken, async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email parameter is required',
        code: 'EMAIL_REQUIRED'
      });
    }

    Logger.debug('User search request', {
      email,
      requesterId: req.user.id,
      requesterRole: req.user.role
    });

    // Find user by email
    const user = await User.findOne({ 
      email: email.toLowerCase().trim(),
      isActive: true 
    }).select('-password -resetPasswordToken -emailVerificationToken');

    if (!user) {
      Logger.debug('User not found in search', { email });
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    Logger.audit('User found via search', 'user_search', {
      searchedEmail: email,
      foundUserId: user._id,
      requesterId: req.user.id
    });

    res.json({
      success: true,
      message: 'User found',
      data: {
        user: {
          id: user._id,
          _id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });

  } catch (error) {
    Logger.error('User search failed', {
      error: error.message,
      stack: error.stack,
      email: req.query.email,
      requesterId: req.user?.id
    });

    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SEARCH_ERROR'
    });
  }
});

// GET /api/users/:userId - Get user by ID
router.get('/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    Logger.debug('User retrieval request', {
      userId,
      requesterId: req.user.id,
      requesterRole: req.user.role
    });

    // Find user by ID
    const user = await User.findById(userId)
      .select('-password -resetPasswordToken -emailVerificationToken');

    if (!user) {
      Logger.debug('User not found by ID', { userId });
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    Logger.audit('User retrieved by ID', 'user_get', {
      retrievedUserId: userId,
      requesterId: req.user.id
    });

    res.json({
      success: true,
      message: 'User retrieved',
      data: {
        user: {
          id: user._id,
          _id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });

  } catch (error) {
    Logger.error('User retrieval failed', {
      error: error.message,
      stack: error.stack,
      userId: req.params.userId,
      requesterId: req.user?.id
    });

    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'RETRIEVAL_ERROR'
    });
  }
});

// GET /api/users - List users (admin only)
router.get('/', authenticateToken, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      role, 
      isActive, 
      search 
    } = req.query;

    Logger.debug('Users list request', {
      page,
      limit,
      role,
      isActive,
      search,
      requesterId: req.user.id,
      requesterRole: req.user.role
    });

    // Build query
    const query = {};
    
    if (role) {
      query.role = role;
    }
    
    if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -resetPasswordToken -emailVerificationToken')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      User.countDocuments(query)
    ]);

    Logger.audit('Users listed', 'users_list', {
      totalFound: total,
      page: parseInt(page),
      limit: parseInt(limit),
      requesterId: req.user.id
    });

    res.json({
      success: true,
      message: 'Users retrieved',
      data: {
        users: users.map(user => ({
          id: user._id,
          _id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        })),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      }
    });

  } catch (error) {
    Logger.error('Users list failed', {
      error: error.message,
      stack: error.stack,
      requesterId: req.user?.id
    });

    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'LIST_ERROR'
    });
  }
});

module.exports = router; 