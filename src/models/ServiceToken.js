const mongoose = require('mongoose');

const serviceTokenSchema = new mongoose.Schema({
  serviceName: {
    type: String,
    required: true,
    unique: true,
    enum: ['database-server', 'tenant-manager', 'auth-server', 'webhook-server']
  },
  
  token: {
    type: String,
    required: true,
    unique: true
  },
  
  description: {
    type: String,
    default: ''
  },
  
  permissions: [{
    type: String,
    required: true
  }],
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  
  lastUsed: {
    type: Date,
    default: null
  },
  
  usageCount: {
    type: Number,
    default: 0
  },
  
  expiresAt: {
    type: Date,
    default: null // null means no expiration
  },
  
  createdBy: {
    type: String,
    default: 'system'
  },
  
  allowedIPs: [{
    type: String
  }],
  
  rateLimit: {
    requestsPerMinute: {
      type: Number,
      default: 1000
    },
    requestsPerHour: {
      type: Number,
      default: 10000
    }
  }
}, {
  timestamps: true
});

// Index for performance
serviceTokenSchema.index({ token: 1 });
serviceTokenSchema.index({ serviceName: 1 });
serviceTokenSchema.index({ isActive: 1 });

// Update lastUsed when token is used
serviceTokenSchema.methods.recordUsage = function() {
  this.lastUsed = new Date();
  this.usageCount += 1;
  return this.save();
};

// Check if token is valid
serviceTokenSchema.methods.isValid = function() {
  if (!this.isActive) return false;
  if (this.expiresAt && this.expiresAt < new Date()) return false;
  return true;
};

module.exports = mongoose.model('ServiceToken', serviceTokenSchema); 