const config = require('../../config/config');

class Logger {
  static log(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      service: 'auth-server',
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

  // Security event logging
  static security(event, severity = 'info', meta = {}) {
    const securityMeta = {
      event,
      severity,
      category: 'security',
      ...meta
    };

    const logLevel = severity === 'critical' || severity === 'high' ? 'error' : 
                     severity === 'medium' ? 'warn' : 'info';

    this.log(logLevel, `Security Event: ${event}`, securityMeta);
  }

  // Audit logging
  static audit(action, resource, meta = {}) {
    const auditMeta = {
      action,
      resource,
      category: 'audit',
      timestamp: new Date().toISOString(),
      ...meta
    };

    this.log('info', `Audit: ${action} on ${resource}`, auditMeta);
  }
}

module.exports = Logger; 