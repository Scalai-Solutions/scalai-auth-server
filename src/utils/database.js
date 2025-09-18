const mongoose = require('mongoose');
const config = require('../../config/config');
const Logger = require('./logger');

class Database {
  static async connect() {
    try {
      const connectionOptions = {
        dbName: config.database.dbName,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        family: 4
      };

      await mongoose.connect(config.database.mongoUri, connectionOptions);
      
      Logger.info('MongoDB connected successfully', {
        database: config.database.dbName,
        environment: config.server.nodeEnv
      });

      // Handle connection events
      mongoose.connection.on('error', (err) => {
        Logger.error('MongoDB connection error', { error: err.message });
      });

      mongoose.connection.on('disconnected', () => {
        Logger.warn('MongoDB disconnected');
      });

      mongoose.connection.on('reconnected', () => {
        Logger.info('MongoDB reconnected');
      });

    } catch (error) {
      Logger.error('MongoDB connection failed', { error: error.message });
      process.exit(1);
    }
  }

  static async disconnect() {
    try {
      await mongoose.connection.close();
      Logger.info('MongoDB connection closed');
    } catch (error) {
      Logger.error('Error closing MongoDB connection', { error: error.message });
    }
  }

  static async clearDatabase() {
    if (config.server.nodeEnv !== 'development') {
      throw new Error('Database clearing is only allowed in development mode');
    }

    try {
      const collections = await mongoose.connection.db.collections();
      
      for (const collection of collections) {
        await collection.deleteMany({});
      }
      
      Logger.info('Database cleared successfully');
    } catch (error) {
      Logger.error('Error clearing database', { error: error.message });
      throw error;
    }
  }
}

module.exports = Database;
