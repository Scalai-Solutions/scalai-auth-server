const mongoose = require('mongoose');

const resourceSchema = new mongoose.Schema({
  // Resource identification
  name: {
    type: String,
    required: [true, 'Resource name is required'],
    unique: true,
    trim: true,
    minlength: [2, 'Resource name must be at least 2 characters'],
    maxlength: [100, 'Resource name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    required: [true, 'Resource description is required'],
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Resource type/category
  type: {
    type: String,
    required: true,
    enum: [
      'subaccount',           // Subaccount management
      'user_management',      // User CRUD operations
      'database_operations',  // Database queries and operations
      'llm_operations',      // LLM API calls
      'system_admin',        // System administration
      'audit_logs',          // Audit log access
      'analytics',           // Analytics and reporting
      'api_keys',            // API key management
      'webhooks',            // Webhook management
      'billing',             // Billing and subscription
      'custom'               // Custom resource type
    ]
  },
  
  // Microservice that owns this resource
  service: {
    type: String,
    required: true,
    enum: ['auth-server', 'tenant-manager', 'database-server', 'shared'],
    index: true
  },
  
  // API endpoints or operations this resource controls
  endpoints: [{
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'],
      required: true
    },
    path: {
      type: String,
      required: true
    },
    description: {
      type: String,
      required: true
    },
    requiredPermissions: [{
      type: String,
      enum: ['read', 'write', 'delete', 'admin'],
      required: true
    }]
  }],
  
  // Default permissions for this resource
  defaultPermissions: {
    super_admin: {
      read: { type: Boolean, default: true },
      write: { type: Boolean, default: true },
      delete: { type: Boolean, default: true },
      admin: { type: Boolean, default: true }
    },
    admin: {
      read: { type: Boolean, default: true },
      write: { type: Boolean, default: true },
      delete: { type: Boolean, default: true },
      admin: { type: Boolean, default: false }
    },
    user: {
      read: { type: Boolean, default: false },
      write: { type: Boolean, default: false },
      delete: { type: Boolean, default: false },
      admin: { type: Boolean, default: false }
    }
  },
  
  // Resource-specific settings
  settings: {
    // Whether this resource requires subaccount context
    requiresSubaccount: {
      type: Boolean,
      default: false
    },
    
    // Whether this resource can be accessed globally by admins
    globalAdminAccess: {
      type: Boolean,
      default: true
    },
    
    // Rate limiting settings for this resource
    rateLimits: {
      perUser: {
        requests: { type: Number, default: 100 },
        windowMs: { type: Number, default: 60000 } // 1 minute
      },
      perSubaccount: {
        requests: { type: Number, default: 1000 },
        windowMs: { type: Number, default: 60000 }
      }
    }
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Who created this resource definition
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
resourceSchema.index({ name: 1, isActive: 1 });
resourceSchema.index({ type: 1, service: 1 });
resourceSchema.index({ 'endpoints.path': 1, 'endpoints.method': 1 });
resourceSchema.index({ createdBy: 1 });

// Static method to find resource by endpoint
resourceSchema.statics.findByEndpoint = async function(method, path, service) {
  try {
    const resource = await this.findOne({
      service,
      isActive: true,
      endpoints: {
        $elemMatch: {
          $or: [
            { method: method.toUpperCase(), path },
            { method: '*', path },
            { method: method.toUpperCase(), path: '*' }
          ]
        }
      }
    });
    
    return resource;
  } catch (error) {
    return null;
  }
};

// Static method to get default permissions for role
resourceSchema.statics.getDefaultPermissions = async function(resourceName, role) {
  try {
    const resource = await this.findOne({ name: resourceName, isActive: true });
    if (!resource) return null;
    
    return resource.defaultPermissions[role] || resource.defaultPermissions.user;
  } catch (error) {
    return null;
  }
};

// Method to check if endpoint requires specific permission
resourceSchema.methods.getRequiredPermissions = function(method, path) {
  const endpoint = this.endpoints.find(ep => 
    (ep.method === method.toUpperCase() || ep.method === '*') &&
    (ep.path === path || ep.path === '*')
  );
  
  return endpoint ? endpoint.requiredPermissions : ['read'];
};

const Resource = mongoose.model('Resource', resourceSchema);

module.exports = Resource; 