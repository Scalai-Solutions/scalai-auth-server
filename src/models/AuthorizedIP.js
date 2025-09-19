const mongoose = require('mongoose');

const authorizedIPSchema = new mongoose.Schema({
  ipAddress: {
    type: String,
    required: [true, 'IP address is required'],
    unique: true,
    trim: true,
    validate: {
      validator: function(v) {
        // Validate IPv4 and IPv6 addresses
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        const ipv6CompressedRegex = /^::1$|^::$/; // localhost IPv6 variations
        
        return ipv4Regex.test(v) || ipv6Regex.test(v) || ipv6CompressedRegex.test(v) || v === 'localhost';
      },
      message: 'Invalid IP address format'
    }
  },
  
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true,
    maxlength: [200, 'Description cannot exceed 200 characters']
  },
  
  // What operations this IP is authorized for
  permissions: {
    changeUserRole: {
      type: Boolean,
      default: false
    },
    createSuperAdmin: {
      type: Boolean,
      default: false
    },
    systemMaintenance: {
      type: Boolean,
      default: false
    }
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Who authorized this IP
  authorizedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Audit trail
  lastUsed: {
    type: Date
  },
  
  usageCount: {
    type: Number,
    default: 0
  },
  
  // Security settings
  expiresAt: {
    type: Date,
    index: { expireAfterSeconds: 0 } // TTL index
  },
  
  // Rate limiting per IP
  dailyUsageLimit: {
    type: Number,
    default: 10 // Max 10 role changes per day per IP
  },
  
  lastResetDate: {
    type: Date,
    default: Date.now
  },
  
  dailyUsageCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance and security
authorizedIPSchema.index({ ipAddress: 1, isActive: 1 });
authorizedIPSchema.index({ authorizedBy: 1 });
authorizedIPSchema.index({ createdAt: -1 });
authorizedIPSchema.index({ lastUsed: -1 });

// Virtual to check if IP is currently authorized
authorizedIPSchema.virtual('isCurrentlyAuthorized').get(function() {
  if (!this.isActive) return false;
  if (this.expiresAt && this.expiresAt < new Date()) return false;
  
  // Check daily usage limit
  const today = new Date().toDateString();
  const lastResetDay = this.lastResetDate ? this.lastResetDate.toDateString() : null;
  
  if (today !== lastResetDay) {
    // Reset daily count if it's a new day
    return true;
  }
  
  return this.dailyUsageCount < this.dailyUsageLimit;
});

// Method to record usage
authorizedIPSchema.methods.recordUsage = async function(operation) {
  const today = new Date();
  const todayString = today.toDateString();
  const lastResetDay = this.lastResetDate ? this.lastResetDate.toDateString() : null;
  
  // Reset daily count if it's a new day
  if (todayString !== lastResetDay) {
    this.dailyUsageCount = 0;
    this.lastResetDate = today;
  }
  
  this.dailyUsageCount += 1;
  this.usageCount += 1;
  this.lastUsed = today;
  
  await this.save();
  
  return {
    dailyUsageRemaining: this.dailyUsageLimit - this.dailyUsageCount,
    totalUsage: this.usageCount
  };
};

// Static method to check if IP is authorized for operation
authorizedIPSchema.statics.isAuthorized = async function(ipAddress, operation = 'changeUserRole') {
  try {
    const authorizedIP = await this.findOne({
      ipAddress,
      isActive: true
    });
    
    if (!authorizedIP) {
      return {
        authorized: false,
        reason: 'IP address not in authorized list'
      };
    }
    
    if (!authorizedIP.isCurrentlyAuthorized) {
      return {
        authorized: false,
        reason: 'IP authorization expired or daily limit exceeded'
      };
    }
    
    if (!authorizedIP.permissions[operation]) {
      return {
        authorized: false,
        reason: `IP not authorized for operation: ${operation}`
      };
    }
    
    return {
      authorized: true,
      authorizedIP
    };
  } catch (error) {
    return {
      authorized: false,
      reason: 'Error checking IP authorization',
      error: error.message
    };
  }
};

// Static method to add authorized IP
authorizedIPSchema.statics.addAuthorizedIP = async function(ipData, authorizedByUserId) {
  try {
    const authorizedIP = new this({
      ...ipData,
      authorizedBy: authorizedByUserId
    });
    
    await authorizedIP.save();
    return { success: true, authorizedIP };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

const AuthorizedIP = mongoose.model('AuthorizedIP', authorizedIPSchema);

module.exports = AuthorizedIP; 