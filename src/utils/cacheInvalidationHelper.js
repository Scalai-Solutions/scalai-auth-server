const axios = require('axios');
const config = require('../../config/config');
const Logger = require('./logger');
const jwt = require('jsonwebtoken');

/**
 * Invalidate database server cache for user permissions
 * @param {string} userId - User ID whose cache should be invalidated
 * @param {string} subaccountId - Subaccount ID (optional)
 */
async function invalidateDatabaseServerCache(userId, subaccountId = null) {
  try {
    // Generate a short-lived JWT token for authentication
    const token = jwt.sign(
      { 
        service: 'auth-server',
        purpose: 'cache_invalidation',
        userId 
      },
      config.jwt.secret,
      { expiresIn: '5m' }
    );

    const payload = {
      type: 'user_permissions',
      userId,
      subaccountId,
      secret: config.cache.databaseServerWebhookSecret
    };

    Logger.debug('Invalidating database server cache', {
      userId,
      subaccountId,
      url: `${config.services.databaseServerUrl}/api/cache/invalidate`
    });

    const response = await axios.post(
      `${config.services.databaseServerUrl}/api/cache/invalidate`,
      payload,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );

    if (response.data.success) {
      Logger.info('Database server cache invalidated successfully', {
        userId,
        subaccountId
      });
    } else {
      Logger.warn('Database server cache invalidation returned unsuccessful', {
        userId,
        subaccountId,
        response: response.data
      });
    }

    return { success: true };
  } catch (error) {
    Logger.error('Failed to invalidate database server cache', {
      error: error.message,
      userId,
      subaccountId,
      url: config.services.databaseServerUrl
    });
    // Don't throw - cache invalidation failure shouldn't block the operation
    return { success: false, error: error.message };
  }
}

/**
 * Invalidate cache for multiple users
 * @param {Array<string>} userIds - Array of user IDs
 * @param {string} subaccountId - Subaccount ID (optional)
 */
async function invalidateDatabaseServerCacheBulk(userIds, subaccountId = null) {
  const results = {
    total: userIds.length,
    successful: 0,
    failed: 0
  };

  Logger.info('Starting bulk cache invalidation', {
    totalUsers: userIds.length,
    subaccountId
  });

  // Process in parallel with limit to avoid overwhelming the database server
  const batchSize = 10;
  for (let i = 0; i < userIds.length; i += batchSize) {
    const batch = userIds.slice(i, i + batchSize);
    const promises = batch.map(userId => invalidateDatabaseServerCache(userId, subaccountId));
    
    const batchResults = await Promise.allSettled(promises);
    batchResults.forEach(result => {
      if (result.status === 'fulfilled' && result.value.success) {
        results.successful++;
      } else {
        results.failed++;
      }
    });
  }

  Logger.info('Bulk cache invalidation completed', results);
  return results;
}

module.exports = {
  invalidateDatabaseServerCache,
  invalidateDatabaseServerCacheBulk
};

