const app = require('./app');
const config = require('../config/config');
const Database = require('./utils/database');
const Logger = require('./utils/logger');

const PORT = config.server.port;

async function startServer() {
  try {
    // Connect to MongoDB
    await Database.connect();
    
    // Clear database in development mode if requested
    if (config.server.nodeEnv === 'development' && process.argv.includes('--clear-db')) {
      Logger.info('Clearing database as requested...');
      await Database.clearDatabase();
      Logger.info('Database cleared successfully');
    }

    const server = app.listen(PORT, () => {
      Logger.info(`🚀 Auth Server running on port ${PORT} in ${config.server.nodeEnv} mode`);
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      Logger.info(`${signal} received`);
      
      server.close(async () => {
        Logger.info('HTTP server closed');
        
        try {
          await Database.disconnect();
          Logger.info('Database connection closed');
          process.exit(0);
        } catch (error) {
          Logger.error('Error during graceful shutdown', { error: error.message });
          process.exit(1);
        }
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    return server;
  } catch (error) {
    Logger.error('Failed to start server', { error: error.message });
    process.exit(1);
  }
}

// Start the server
startServer();
