const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const DatabaseSetup = require('../utils/setupDatabase');

// Health check endpoint
router.get('/', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.json({
    success: true,
    message: 'Auth Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0',
    database: {
      status: dbStatus,
      name: mongoose.connection.name
    }
  });
});

// Detailed health check
router.get('/detailed', async (req, res) => {
  try {
    const dbStats = await DatabaseSetup.getStats();
    
    const healthData = {
      success: true,
      message: 'Auth Server is healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024 * 100) / 100,
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024 * 100) / 100,
        external: Math.round(process.memoryUsage().external / 1024 / 1024 * 100) / 100
      },
      system: {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version
      },
      database: {
        status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        name: mongoose.connection.name,
        host: mongoose.connection.host,
        stats: dbStats
      }
    };

    res.json(healthData);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Health check failed',
      error: error.message
    });
  }
});

module.exports = router;
