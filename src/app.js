const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const config = require('../config/config');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const rateLimiter = require('./middleware/rateLimiter');
const { 
  securityHeaders, 
  suspiciousIPDetector, 
  deviceFingerprint,
  sensitiveOperationLimiter 
} = require('./middleware/securityMiddleware');

// Import routes
const authRoutes = require('./routes/authRoutes');
const healthRoutes = require('./routes/healthRoutes');
const rbacRoutes = require('./routes/rbacRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());
app.use(securityHeaders);
app.use(cors({
  origin: config.cors.origin,
  credentials: true
}));

// Logging middleware
if (config.server.nodeEnv !== 'test') {
  app.use(morgan('combined'));
}

// Rate limiting
app.use(rateLimiter);

// Security detection middleware
app.use(suspiciousIPDetector);
app.use(deviceFingerprint);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Routes with additional security for sensitive operations
app.use('/api/health', healthRoutes);

// Apply sensitive operation rate limiting to auth routes
app.use('/api/auth/login', sensitiveOperationLimiter(5, 15)); // 5 attempts per 15 minutes
app.use('/api/auth/register', sensitiveOperationLimiter(3, 60)); // 3 attempts per hour
app.use('/api/auth/reset-password', sensitiveOperationLimiter(3, 60)); // 3 attempts per hour
app.use('/api/auth/request-reset-password', sensitiveOperationLimiter(5, 15)); // 5 attempts per 15 minutes

app.use('/api/auth', authRoutes);
app.use('/api/rbac', rbacRoutes); // Add RBAC management routes
app.use('/api/users', userRoutes); // Add user management routes

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Global error handler
app.use(errorHandler);

module.exports = app;
