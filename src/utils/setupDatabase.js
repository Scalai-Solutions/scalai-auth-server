const Database = require('./database');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const Logger = require('./logger');

class DatabaseSetup {
  static async createIndexes() {
    try {
      Logger.info('Creating database indexes...');
      
      // Create indexes for User model
      await User.createIndexes();
      
      // Create indexes for RefreshToken model
      await RefreshToken.createIndexes();
      
      Logger.info('Database indexes created successfully');
    } catch (error) {
      Logger.error('Error creating database indexes', { error: error.message });
      throw error;
    }
  }

  static async createAdminUser(adminData) {
    try {
      const existingAdmin = await User.findOne({ email: adminData.email });
      
      if (existingAdmin) {
        Logger.info('Admin user already exists', { email: adminData.email });
        return existingAdmin;
      }

      const admin = new User(adminData);
      await admin.save();
      
      Logger.info('Admin user created successfully', { email: adminData.email });
      return admin;
    } catch (error) {
      Logger.error('Error creating admin user', { error: error.message });
      throw error;
    }
  }

  static async setupDatabase() {
    try {
      await Database.connect();
      await this.createIndexes();
      
      Logger.info('Database setup completed successfully');
    } catch (error) {
      Logger.error('Database setup failed', { error: error.message });
      throw error;
    }
  }

  static async getStats() {
    try {
      const userCount = await User.countDocuments();
      const activeUserCount = await User.countDocuments({ isActive: true });
      const refreshTokenCount = await RefreshToken.countDocuments();
      const activeTokenCount = await RefreshToken.countDocuments({ 
        isRevoked: false, 
        expiresAt: { $gt: new Date() } 
      });

      return {
        users: {
          total: userCount,
          active: activeUserCount
        },
        refreshTokens: {
          total: refreshTokenCount,
          active: activeTokenCount
        }
      };
    } catch (error) {
      Logger.error('Error getting database stats', { error: error.message });
      throw error;
    }
  }
}

module.exports = DatabaseSetup;
