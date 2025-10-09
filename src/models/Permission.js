const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  // User who has the permission
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  // Resource this permission applies to
  resourceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Resource',
    required: true,
    index: true
  },
  
  // Subaccount context (null for global permissions)
  subaccountId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Subaccount',
    default: null,
    index: true
  },
  
  // Composite role: combines user's global role with subaccount-specific role
  compositeRole: {
    globalRole: {
      type: String,
      enum: ['user', 'admin', 'super_admin'],
      required: true
    },
    subaccountRole: {
      type: String,
      enum: ['viewer', 'editor', 'admin', 'owner', null],
      default: null
    },
    // Computed effective role (highest privilege)
    effectiveRole: {
      type: String,
      enum: ['viewer', 'editor', 'admin', 'owner', 'super_admin'],
      required: true
    }
  },
  
  // Specific permissions for this user-resource-subaccount combination
  permissions: {
    read: {
      type: Boolean,
      default: false
    },
    write: {
      type: Boolean,
      default: false
    },
    delete: {
      type: Boolean,
      default: false
    },
    admin: {
      type: Boolean,
      default: false
    }
  },
  
  // Permission metadata
  grantedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  grantedAt: {
    type: Date,
    default: Date.now
  },
  
  expiresAt: {
    type: Date,
    default: null,
    index: { expireAfterSeconds: 0 } // TTL index
  },
  
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  
  // Audit trail
  lastUsed: {
    type: Date,
    default: Date.now
  },
  
  usageCount: {
    type: Number,
    default: 0
  },
  
  // Additional constraints
  constraints: {
    // IP restrictions
    allowedIPs: [{
      type: String
    }],
    
    // Time-based restrictions
    allowedHours: {
      start: { type: Number, min: 0, max: 23 },
      end: { type: Number, min: 0, max: 23 }
    },
    
    // Usage limits
    dailyUsageLimit: {
      type: Number,
      default: null // null = no limit
    },
    
    monthlyUsageLimit: {
      type: Number,
      default: null
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Compound indexes for efficient queries
permissionSchema.index({ userId: 1, resourceId: 1, subaccountId: 1 }, { unique: true });
permissionSchema.index({ userId: 1, subaccountId: 1, isActive: 1 });
permissionSchema.index({ resourceId: 1, isActive: 1 });
permissionSchema.index({ 'compositeRole.effectiveRole': 1, isActive: 1 });
permissionSchema.index({ grantedBy: 1, createdAt: -1 });

// Virtual to check if permission is currently valid
permissionSchema.virtual('isValid').get(function() {
  if (!this.isActive) return false;
  if (this.expiresAt && this.expiresAt < new Date()) return false;
  
  // Check time constraints
  if (this.constraints.allowedHours.start !== undefined && this.constraints.allowedHours.end !== undefined) {
    const currentHour = new Date().getHours();
    const start = this.constraints.allowedHours.start;
    const end = this.constraints.allowedHours.end;
    
    if (start <= end) {
      // Normal range (e.g., 9-17)
      if (currentHour < start || currentHour > end) return false;
    } else {
      // Overnight range (e.g., 22-6)
      if (currentHour < start && currentHour > end) return false;
    }
  }
  
  return true;
});

// Pre-save middleware to compute effective role
permissionSchema.pre('save', function(next) {
  // Compute effective role based on global and subaccount roles
  const globalRole = this.compositeRole.globalRole;
  const subaccountRole = this.compositeRole.subaccountRole;
  
  // Super admin always takes precedence
  if (globalRole === 'super_admin') {
    this.compositeRole.effectiveRole = 'super_admin';
  }
  // Global admin takes precedence over subaccount roles
  else if (globalRole === 'admin') {
    this.compositeRole.effectiveRole = 'admin';
  }
  // Use subaccount role if present, otherwise use global role
  else if (subaccountRole) {
    this.compositeRole.effectiveRole = subaccountRole;
  } else {
    this.compositeRole.effectiveRole = globalRole;
  }
  
  next();
});

// Static method to check user permission for resource
permissionSchema.statics.checkPermission = async function(userId, resourceName, requiredPermission, subaccountId = null) {
  try {
    // First get the resource
    const Resource = require('./Resource');
    const resource = await Resource.findOne({ name: resourceName, isActive: true });
    if (!resource) {
      return { hasPermission: false, reason: 'Resource not found' };
    }
    
    // Get user's global role
    const User = require('./User');
    const user = await User.findById(userId);
    if (!user || !user.isActive) {
      return { hasPermission: false, reason: 'User not found or inactive' };
    }
    
    // Super admins have access to everything
    if (user.role === 'super_admin') {
      return { 
        hasPermission: true, 
        reason: 'Super admin access',
        effectiveRole: 'super_admin'
      };
    }
    
    // Global admins have access to all resources and all permissions
    // This means admins automatically have read, write, delete, and admin permissions
    // for all resources across all subaccounts without explicit permission grants
    if (user.role === 'admin') {
      return {
        hasPermission: true,
        reason: 'Global admin access - automatic full permissions',
        effectiveRole: 'admin'
      };
    }
    
    // For subaccount-specific resources, check subaccount permissions
    if (subaccountId && resource.settings.requiresSubaccount) {
      const UserSubaccount = require('./UserSubaccount');
      const userSubaccount = await UserSubaccount.findOne({
        userId,
        subaccountId,
        isActive: true
      });
      
      if (userSubaccount) {
        const hasRequiredPermission = userSubaccount.permissions[requiredPermission] === true;
        return {
          hasPermission: hasRequiredPermission,
          reason: hasRequiredPermission ? 'Subaccount permission granted' : 'Subaccount permission denied',
          effectiveRole: userSubaccount.role,
          subaccountRole: userSubaccount.role
        };
      }
    }
    
    // Check explicit permissions
    const permission = await this.findOne({
      userId,
      resourceId: resource._id,
      subaccountId: subaccountId || null,
      isActive: true
    });
    
    if (permission && permission.isValid) {
      const hasRequiredPermission = permission.permissions[requiredPermission] === true;
      await permission.updateOne({ 
        lastUsed: new Date(), 
        $inc: { usageCount: 1 } 
      });
      
      return {
        hasPermission: hasRequiredPermission,
        reason: hasRequiredPermission ? 'Explicit permission granted' : 'Explicit permission insufficient',
        effectiveRole: permission.compositeRole.effectiveRole,
        permissionId: permission._id
      };
    }
    
    // Fall back to default permissions based on user role
    const defaultPermissions = resource.defaultPermissions[user.role] || resource.defaultPermissions.user;
    const hasRequiredPermission = defaultPermissions[requiredPermission] === true;
    
    return {
      hasPermission: hasRequiredPermission,
      reason: hasRequiredPermission ? 'Default role permission' : 'Default role permission insufficient',
      effectiveRole: user.role
    };
    
  } catch (error) {
    return { 
      hasPermission: false, 
      reason: 'Permission check failed', 
      error: error.message 
    };
  }
};

// Static method to grant permission
permissionSchema.statics.grantPermission = async function(grantData) {
  try {
    const {
      userId,
      resourceName,
      permissions,
      subaccountId = null,
      grantedBy,
      expiresAt = null,
      constraints = {}
    } = grantData;
    
    // Get resource
    const Resource = require('./Resource');
    const resource = await Resource.findOne({ name: resourceName, isActive: true });
    if (!resource) {
      return { success: false, error: 'Resource not found' };
    }
    
    // Get user to determine composite role
    const User = require('./User');
    const user = await User.findById(userId);
    if (!user) {
      return { success: false, error: 'User not found' };
    }
    
    // Get subaccount role if applicable
    let subaccountRole = null;
    if (subaccountId) {
      const UserSubaccount = require('./UserSubaccount');
      const userSubaccount = await UserSubaccount.findOne({
        userId,
        subaccountId,
        isActive: true
      });
      subaccountRole = userSubaccount ? userSubaccount.role : null;
    }
    
    // Create or update permission
    const permission = await this.findOneAndUpdate(
      { userId, resourceId: resource._id, subaccountId },
      {
        compositeRole: {
          globalRole: user.role,
          subaccountRole,
          effectiveRole: user.role === 'super_admin' ? 'super_admin' : 
                        user.role === 'admin' ? 'admin' : 
                        subaccountRole || user.role
        },
        permissions,
        grantedBy,
        grantedAt: new Date(),
        expiresAt,
        constraints,
        isActive: true
      },
      { upsert: true, new: true }
    );
    
    return { success: true, permission };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Static method to revoke permission
permissionSchema.statics.revokePermission = async function(userId, resourceName, subaccountId = null) {
  try {
    const Resource = require('./Resource');
    const resource = await Resource.findOne({ name: resourceName, isActive: true });
    if (!resource) {
      return { success: false, error: 'Resource not found' };
    }
    
    const result = await this.findOneAndUpdate(
      { userId, resourceId: resource._id, subaccountId },
      { isActive: false },
      { new: true }
    );
    
    return { success: true, revoked: !!result };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

const Permission = mongoose.model('Permission', permissionSchema);

module.exports = Permission; 