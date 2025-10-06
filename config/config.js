require('dotenv').config();

const config = {
  server: {
    port: process.env.PORT || 3001,
    nodeEnv: process.env.NODE_ENV || 'development'
  },
  
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  },
  
  database: {
    mongoUri: process.env.MONGODB_URI,
    dbName: process.env.DB_NAME || 'scalai_auth'
  },
  
  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12
  },
  
  // Encryption settings for subaccount connection strings
  encryption: {
    key: process.env.ENCRYPTION_KEY || 'default-encryption-key-change-in-production',
    algorithm: 'aes-256-gcm'
  },
  
  // Redis configuration for session management and caching
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT) || 6379,
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB) || 0,
    ttl: parseInt(process.env.REDIS_TTL) || 3600 // 1 hour default
  },
  
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000'
  },

  // Service tokens for inter-service authentication
  serviceTokens: {
    tenantManager: process.env.TENANT_MANAGER_SERVICE_TOKEN
  },

  // Microservice URLs
  services: {
    tenantManagerUrl: process.env.TENANT_MANAGER_URL || 'http://localhost:3003',
    databaseServerUrl: process.env.DATABASE_SERVER_URL || 'http://localhost:3002'
  },

  // Cache invalidation
  cache: {
    databaseServerWebhookSecret: process.env.DATABASE_SERVER_CACHE_WEBHOOK_SECRET
  }
};

// Validate required config
const requiredConfig = [
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'MONGODB_URI',
  'ENCRYPTION_KEY'
];

requiredConfig.forEach(key => {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
});

module.exports = config;
