const config = require('../../config/config');

class Logger {
  static log(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      ...meta
    };

    if (config.server.nodeEnv === 'development') {
      console.log(`[${timestamp}] ${level.toUpperCase()}: ${message}`, meta);
    } else {
      // In production, you might want to use a proper logging library like Winston
      console.log(JSON.stringify(logEntry));
    }
  }

  static info(message, meta = {}) {
    this.log('info', message, meta);
  }

  static error(message, meta = {}) {
    this.log('error', message, meta);
  }

  static warn(message, meta = {}) {
    this.log('warn', message, meta);
  }

  static debug(message, meta = {}) {
    if (config.server.nodeEnv === 'development') {
      this.log('debug', message, meta);
    }
  }
}

module.exports = Logger; 