const axios = require('axios');
const Logger = require('./logger');
const config = require('../../config/config');

class CacheInvalidationService {
  constructor() {
    // List of microservices that need cache invalidation
    this.services = [
      {
        name: 'database-server',
        url: config.services?.databaseServer?.url || 'http://localhost:3002',
        webhook: '/api/cache/invalidate'
      },
      {
        name: 'tenant-manager',
        url: config.services?.tenantManager?.url || 'http://localhost:3003',
        webhook: '/api/cache/invalidate'
      }
      // Add more services as needed
    ];

    this.webhookSecret = process.env.CACHE_WEBHOOK_SECRET || 'default-secret';
  }

  // Notify all services about user permission changes
  async invalidateUserPermissions(userId, subaccountId = null, reason = 'permission_change') {
    const payload = {
      type: 'user_permissions',
      userId,
      subaccountId,
      reason,
      timestamp: new Date().toISOString(),
      secret: this.webhookSecret
    };

    await this._notifyServices(payload, `User permissions invalidation for ${userId}`);
  }

  // Notify all services about resource changes
  async invalidateResource(resourceName, reason = 'resource_change') {
    const payload = {
      type: 'resource',
      resourceName,
      reason,
      timestamp: new Date().toISOString(),
      secret: this.webhookSecret
    };

    await this._notifyServices(payload, `Resource invalidation for ${resourceName}`);
  }

  // Notify all services to clear all caches
  async clearAllCaches(reason = 'system_update') {
    const payload = {
      type: 'clear_all',
      reason,
      timestamp: new Date().toISOString(),
      secret: this.webhookSecret
    };

    await this._notifyServices(payload, 'Clear all caches');
  }

  // Internal method to notify all registered services
  async _notifyServices(payload, description) {
    const notifications = this.services.map(service => 
      this._notifyService(service, payload, description)
    );

    const results = await Promise.allSettled(notifications);
    
    // Log results
    let successCount = 0;
    let failureCount = 0;

    results.forEach((result, index) => {
      const service = this.services[index];
      if (result.status === 'fulfilled') {
        successCount++;
        Logger.debug('Cache invalidation notification sent', {
          service: service.name,
          description,
          payload: { ...payload, secret: '[REDACTED]' }
        });
      } else {
        failureCount++;
        Logger.error('Cache invalidation notification failed', {
          service: service.name,
          description,
          error: result.reason.message,
          payload: { ...payload, secret: '[REDACTED]' }
        });
      }
    });

    Logger.info('Cache invalidation notifications completed', {
      description,
      totalServices: this.services.length,
      successful: successCount,
      failed: failureCount
    });

    return { successCount, failureCount, total: this.services.length };
  }

  // Internal method to notify a single service
  async _notifyService(service, payload, description) {
    try {
      const response = await axios.post(
        `${service.url}${service.webhook}`,
        payload,
        {
          timeout: 5000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'ScalAI-AuthServer-CacheInvalidation/1.0'
          }
        }
      );

      if (!response.data.success) {
        throw new Error(`Service responded with error: ${response.data.message}`);
      }

      return response.data;
    } catch (error) {
      // Don't throw error here - let Promise.allSettled handle it
      throw new Error(`Failed to notify ${service.name}: ${error.message}`);
    }
  }

  // Health check for cache invalidation service
  async healthCheck() {
    const checks = this.services.map(async (service) => {
      try {
        const response = await axios.get(`${service.url}/api/health`, { timeout: 3000 });
        return {
          service: service.name,
          status: response.status === 200 ? 'healthy' : 'unhealthy',
          url: service.url
        };
      } catch (error) {
        return {
          service: service.name,
          status: 'unreachable',
          url: service.url,
          error: error.message
        };
      }
    });

    const results = await Promise.allSettled(checks);
    
    return results.map((result, index) => 
      result.status === 'fulfilled' ? result.value : {
        service: this.services[index].name,
        status: 'error',
        url: this.services[index].url,
        error: result.reason.message
      }
    );
  }
}

// Export singleton instance
const cacheInvalidationService = new CacheInvalidationService();

module.exports = {
  CacheInvalidationService,
  cacheInvalidationService
}; 