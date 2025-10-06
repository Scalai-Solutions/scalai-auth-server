const RefreshToken = require('../models/RefreshToken');
const Logger = require('../utils/logger');

// IP-based rate limiting for sensitive operations
const sensitiveOperationLimiter = (maxAttempts = 50, windowMinutes = 15) => {
  const attempts = new Map();

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = windowMinutes * 60 * 1000;

    // Clean up old entries
    for (const [key, data] of attempts.entries()) {
      if (now - data.firstAttempt > windowMs) {
        attempts.delete(key);
      }
    }

    const ipAttempts = attempts.get(ip) || { count: 0, firstAttempt: now };

    if (ipAttempts.count >= maxAttempts) {
      Logger.warn('Sensitive operation rate limit exceeded', { 
        ip, 
        attempts: ipAttempts.count,
        endpoint: req.path 
      });
      
      return res.status(429).json({
        success: false,
        message: 'Too many attempts. Please try again later.',
        retryAfter: Math.ceil((ipAttempts.firstAttempt + windowMs - now) / 1000)
      });
    }

    // Increment attempts
    ipAttempts.count++;
    attempts.set(ip, ipAttempts);

    next();
  };
};

// Detect and block suspicious IP patterns
const suspiciousIPDetector = async (req, res, next) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const now = new Date();
    const lastHour = new Date(now.getTime() - 60 * 60 * 1000);

    // Check for excessive token creation from this IP
    const recentTokens = await RefreshToken.countDocuments({
      ipAddress: ip,
      createdAt: { $gte: lastHour }
    });

    if (recentTokens > 10) { // More than 10 logins from same IP in last hour
      Logger.warn('Suspicious IP activity detected', { 
        ip, 
        recentTokens,
        endpoint: req.path 
      });

      // Could implement IP blocking here
      // For now, just log and continue with extra monitoring
      req.suspiciousIP = true;
    }

    next();
  } catch (error) {
    Logger.error('Error in suspicious IP detection', { error: error.message });
    next(); // Continue on error
  }
};

// Geolocation change detector (basic implementation)
const geolocationChangeDetector = async (req, res, next) => {
  try {
    if (!req.user) return next();

    const currentIP = req.ip || req.connection.remoteAddress;
    
    // Get user's recent tokens
    const recentToken = await RefreshToken.findOne({
      user: req.user.id,
      isRevoked: false
    }).sort({ createdAt: -1 });

    if (recentToken && recentToken.ipAddress !== currentIP) {
      // Simple geolocation check based on IP ranges
      const isLikelyDifferentLocation = !isSameSubnet(currentIP, recentToken.ipAddress);
      
      if (isLikelyDifferentLocation) {
        Logger.warn('Potential geolocation change detected', {
          userId: req.user.id,
          previousIP: recentToken.ipAddress,
          currentIP,
          endpoint: req.path
        });

        req.geolocationChange = true;
      }
    }

    next();
  } catch (error) {
    Logger.error('Error in geolocation detection', { error: error.message });
    next();
  }
};

// Helper function to check if IPs are in same subnet (basic check)
const isSameSubnet = (ip1, ip2) => {
  if (!ip1 || !ip2) return false;
  
  // Very basic check - compare first 3 octets for IPv4
  const parts1 = ip1.split('.');
  const parts2 = ip2.split('.');
  
  if (parts1.length !== 4 || parts2.length !== 4) return false;
  
  return parts1.slice(0, 3).join('.') === parts2.slice(0, 3).join('.');
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Add security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  
  next();
};

// Device fingerprinting (basic)
const deviceFingerprint = (req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  const acceptLanguage = req.get('Accept-Language') || '';
  const acceptEncoding = req.get('Accept-Encoding') || '';
  
  // Create a simple fingerprint
  const fingerprint = Buffer.from(
    `${userAgent}|${acceptLanguage}|${acceptEncoding}`
  ).toString('base64');
  
  req.deviceFingerprint = fingerprint;
  next();
};

module.exports = {
  sensitiveOperationLimiter,
  suspiciousIPDetector,
  geolocationChangeDetector,
  securityHeaders,
  deviceFingerprint
};
