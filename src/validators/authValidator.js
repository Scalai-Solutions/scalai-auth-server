const Joi = require('joi');
const mongoose = require('mongoose');

const registerSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  
  password: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'Password is required'
    }),
  
  firstName: Joi.string()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'First name must be at least 2 characters long',
      'string.max': 'First name cannot exceed 50 characters',
      'any.required': 'First name is required'
    }),
  
  lastName: Joi.string()
    .min(2)
    .max(50)
    .required()
    .messages({
      'string.min': 'Last name must be at least 2 characters long',
      'string.max': 'Last name cannot exceed 50 characters',
      'any.required': 'Last name is required'
    })
});

const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  
  password: Joi.string()
    .required()
    .messages({
      'any.required': 'Password is required'
    })
});

const resetPasswordRequestSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    })
});

const resetPasswordSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'any.required': 'Reset token is required'
    }),
  
  newPassword: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'New password is required'
    })
});

const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string()
    .required()
    .messages({
      'any.required': 'Refresh token is required'
    })
});

// Validation middleware
const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors
      });
    }
    
    next();
  };
};

// Validate change user role request
const validateChangeUserRole = (req, res, next) => {
  const { userId, newRole, reason } = req.body;
  const errors = [];

  // Validate userId
  if (!userId) {
    errors.push({ field: 'userId', message: 'User ID is required' });
  } else if (!mongoose.Types.ObjectId.isValid(userId)) {
    errors.push({ field: 'userId', message: 'Invalid user ID format' });
  }

  // Validate newRole
  const validRoles = ['user', 'admin', 'super_admin'];
  if (!newRole) {
    errors.push({ field: 'newRole', message: 'New role is required' });
  } else if (!validRoles.includes(newRole)) {
    errors.push({ 
      field: 'newRole', 
      message: 'Invalid role specified',
      validRoles 
    });
  }

  // Validate reason for super_admin role
  if (newRole === 'super_admin') {
    if (!reason || typeof reason !== 'string') {
      errors.push({ 
        field: 'reason', 
        message: 'Reason is required for super admin role assignment' 
      });
    } else if (reason.trim().length < 10) {
      errors.push({ 
        field: 'reason', 
        message: 'Reason must be at least 10 characters long for super admin role' 
      });
    } else if (reason.trim().length > 500) {
      errors.push({ 
        field: 'reason', 
        message: 'Reason cannot exceed 500 characters' 
      });
    }
  }

  // Optional reason validation for other roles
  if (reason && typeof reason === 'string' && reason.length > 500) {
    errors.push({ 
      field: 'reason', 
      message: 'Reason cannot exceed 500 characters' 
    });
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
      errors
    });
  }

  next();
};

module.exports = {
  validateRegister: validate(registerSchema),
  validateLogin: validate(loginSchema),
  validateResetPasswordRequest: validate(resetPasswordRequestSchema),
  validateResetPassword: validate(resetPasswordSchema),
  validateRefreshToken: validate(refreshTokenSchema),
  validateChangeUserRole: validateChangeUserRole
}; 