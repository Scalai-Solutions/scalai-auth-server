const crypto = require('crypto');
const ServiceToken = require('../models/ServiceToken');
const Logger = require('../utils/logger');

// Generate a secure service token
const generateServiceToken = () => {
  return crypto.randomBytes(64).toString('hex');
};

// Create a new service token
const createServiceToken = async (req, res) => {
  try {
    const { serviceName, description, permissions, allowedIPs, rateLimit } = req.body;

    // Validate required fields
    if (!serviceName || !permissions || !Array.isArray(permissions)) {
      return res.status(400).json({
        success: false,
        message: 'Service name and permissions array are required'
      });
    }

    // Check if service token already exists
    const existingToken = await ServiceToken.findOne({ serviceName });
    if (existingToken) {
      return res.status(409).json({
        success: false,
        message: 'Service token already exists for this service'
      });
    }

    // Generate secure token
    const token = generateServiceToken();

    // Create service token
    const serviceToken = new ServiceToken({
      serviceName,
      token,
      description: description || `Service token for ${serviceName}`,
      permissions,
      allowedIPs: allowedIPs || [],
      rateLimit: rateLimit || {
        requestsPerMinute: 1000,
        requestsPerHour: 10000
      },
      createdBy: req.user?.email || 'system'
    });

    await serviceToken.save();

    Logger.info('Service token created', {
      serviceName,
      createdBy: req.user?.email || 'system',
      permissions
    });

    res.status(201).json({
      success: true,
      message: 'Service token created successfully',
      data: {
        serviceName,
        token, // Only return token once during creation
        description: serviceToken.description,
        permissions,
        isActive: serviceToken.isActive,
        createdAt: serviceToken.createdAt
      }
    });

  } catch (error) {
    Logger.error('Failed to create service token', {
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      message: 'Failed to create service token',
      error: error.message
    });
  }
};

// Get all service tokens (without actual token values)
const getServiceTokens = async (req, res) => {
  try {
    const tokens = await ServiceToken.find({}, {
      token: 0 // Exclude actual token from response
    }).sort({ createdAt: -1 });

    res.json({
      success: true,
      data: tokens
    });

  } catch (error) {
    Logger.error('Failed to get service tokens', {
      error: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to get service tokens',
      error: error.message
    });
  }
};

// Get a specific service token (without actual token value)
const getServiceToken = async (req, res) => {
  try {
    const { serviceName } = req.params;

    const serviceToken = await ServiceToken.findOne(
      { serviceName },
      { token: 0 } // Exclude actual token from response
    );

    if (!serviceToken) {
      return res.status(404).json({
        success: false,
        message: 'Service token not found'
      });
    }

    res.json({
      success: true,
      data: serviceToken
    });

  } catch (error) {
    Logger.error('Failed to get service token', {
      serviceName: req.params.serviceName,
      error: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to get service token',
      error: error.message
    });
  }
};

// Update a service token
const updateServiceToken = async (req, res) => {
  try {
    const { serviceName } = req.params;
    const { description, permissions, allowedIPs, rateLimit, isActive } = req.body;

    const serviceToken = await ServiceToken.findOne({ serviceName });

    if (!serviceToken) {
      return res.status(404).json({
        success: false,
        message: 'Service token not found'
      });
    }

    // Update fields
    if (description !== undefined) serviceToken.description = description;
    if (permissions !== undefined) serviceToken.permissions = permissions;
    if (allowedIPs !== undefined) serviceToken.allowedIPs = allowedIPs;
    if (rateLimit !== undefined) serviceToken.rateLimit = rateLimit;
    if (isActive !== undefined) serviceToken.isActive = isActive;

    await serviceToken.save();

    Logger.info('Service token updated', {
      serviceName,
      updatedBy: req.user?.email || 'system'
    });

    res.json({
      success: true,
      message: 'Service token updated successfully',
      data: {
        serviceName: serviceToken.serviceName,
        description: serviceToken.description,
        permissions: serviceToken.permissions,
        isActive: serviceToken.isActive,
        updatedAt: serviceToken.updatedAt
      }
    });

  } catch (error) {
    Logger.error('Failed to update service token', {
      serviceName: req.params.serviceName,
      error: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to update service token',
      error: error.message
    });
  }
};

// Regenerate a service token
const regenerateServiceToken = async (req, res) => {
  try {
    const { serviceName } = req.params;

    const serviceToken = await ServiceToken.findOne({ serviceName });

    if (!serviceToken) {
      return res.status(404).json({
        success: false,
        message: 'Service token not found'
      });
    }

    // Generate new token
    const newToken = generateServiceToken();
    serviceToken.token = newToken;
    serviceToken.usageCount = 0;
    serviceToken.lastUsed = null;

    await serviceToken.save();

    Logger.info('Service token regenerated', {
      serviceName,
      regeneratedBy: req.user?.email || 'system'
    });

    res.json({
      success: true,
      message: 'Service token regenerated successfully',
      data: {
        serviceName,
        token: newToken, // Return new token
        regeneratedAt: new Date()
      }
    });

  } catch (error) {
    Logger.error('Failed to regenerate service token', {
      serviceName: req.params.serviceName,
      error: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to regenerate service token',
      error: error.message
    });
  }
};

// Delete a service token
const deleteServiceToken = async (req, res) => {
  try {
    const { serviceName } = req.params;

    const serviceToken = await ServiceToken.findOneAndDelete({ serviceName });

    if (!serviceToken) {
      return res.status(404).json({
        success: false,
        message: 'Service token not found'
      });
    }

    Logger.info('Service token deleted', {
      serviceName,
      deletedBy: req.user?.email || 'system'
    });

    res.json({
      success: true,
      message: 'Service token deleted successfully'
    });

  } catch (error) {
    Logger.error('Failed to delete service token', {
      serviceName: req.params.serviceName,
      error: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to delete service token',
      error: error.message
    });
  }
};

// Validate a service token (internal use)
const validateServiceToken = async (token) => {
  try {
    const serviceToken = await ServiceToken.findOne({ token });

    if (!serviceToken || !serviceToken.isValid()) {
      return null;
    }

    // Record usage
    await serviceToken.recordUsage();

    return {
      serviceName: serviceToken.serviceName,
      permissions: serviceToken.permissions,
      allowedIPs: serviceToken.allowedIPs,
      rateLimit: serviceToken.rateLimit
    };

  } catch (error) {
    Logger.error('Failed to validate service token', {
      error: error.message
    });
    return null;
  }
};

module.exports = {
  createServiceToken,
  getServiceTokens,
  getServiceToken,
  updateServiceToken,
  regenerateServiceToken,
  deleteServiceToken,
  validateServiceToken
}; 