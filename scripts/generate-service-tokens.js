#!/usr/bin/env node

const mongoose = require('mongoose');
const crypto = require('crypto');
const config = require('../config/config');

// Import models
const ServiceToken = require('../src/models/ServiceToken');

// Service configurations
const serviceConfigs = [
  {
    serviceName: 'database-server',
    description: 'Database server service token for CRUD operations and connection management',
    permissions: [
      'subaccounts:read',
      'database:execute',
      'connections:manage',
      'cache:read',
      'cache:write'
    ]
  },
  {
    serviceName: 'tenant-manager',
    description: 'Tenant manager service token for subaccount and user management',
    permissions: [
      'subaccounts:read',
      'subaccounts:write',
      'users:read',
      'users:write',
      'permissions:read',
      'audit:write'
    ]
  },
  {
    serviceName: 'auth-server',
    description: 'Auth server service token for internal authentication operations',
    permissions: [
      'users:read',
      'permissions:read',
      'tokens:validate',
      'audit:write'
    ]
  },
  {
    serviceName: 'webhook-server',
    description: 'Webhook server service token for event notifications and tenant-manager integration',
    permissions: [
      'subaccounts:read',
      'subaccounts:write',
      'users:read',
      'users:write',
      'audit:write',
      'permissions:read'
    ]
  }
];

// Generate secure service token
const generateServiceToken = () => {
  return crypto.randomBytes(64).toString('hex');
};

async function generateServiceTokens() {
  try {
    console.log('🚀 Starting service token generation...');
    
    // Connect to MongoDB
    await mongoose.connect(config.database.mongoUri, {
      dbName: config.database.dbName
    });
    console.log('✅ Connected to MongoDB');

    const generatedTokens = [];

    for (const serviceConfig of serviceConfigs) {
      try {
        // Check if service token already exists
        const existingToken = await ServiceToken.findOne({ 
          serviceName: serviceConfig.serviceName 
        });

        if (existingToken) {
          console.log(`⚠️  Service token already exists for ${serviceConfig.serviceName}`);
          console.log(`   Token: ${existingToken.token.substring(0, 16)}...`);
          generatedTokens.push({
            serviceName: serviceConfig.serviceName,
            token: existingToken.token,
            status: 'existing'
          });
          continue;
        }

        // Generate new token
        const token = generateServiceToken();

        // Create service token
        const serviceToken = new ServiceToken({
          serviceName: serviceConfig.serviceName,
          token,
          description: serviceConfig.description,
          permissions: serviceConfig.permissions,
          rateLimit: {
            requestsPerMinute: 1000,
            requestsPerHour: 50000
          },
          createdBy: 'system-script'
        });

        await serviceToken.save();

        console.log(`✅ Created service token for ${serviceConfig.serviceName}`);
        console.log(`   Token: ${token.substring(0, 16)}...`);
        console.log(`   Permissions: ${serviceConfig.permissions.join(', ')}`);

        generatedTokens.push({
          serviceName: serviceConfig.serviceName,
          token: token,
          status: 'created'
        });

      } catch (error) {
        console.error(`❌ Failed to create token for ${serviceConfig.serviceName}:`, error.message);
      }
    }

    console.log('\n📋 Service Token Summary:');
    console.log('========================');
    
    for (const tokenInfo of generatedTokens) {
      console.log(`\n${tokenInfo.serviceName.toUpperCase()}:`);
      console.log(`Status: ${tokenInfo.status}`);
      console.log(`Token: ${tokenInfo.token}`);
      console.log(`Environment Variable: ${tokenInfo.serviceName.toUpperCase().replace('-', '_')}_SERVICE_TOKEN`);
    }

    console.log('\n🔧 Environment Variables to Add:');
    console.log('================================');
    
    for (const tokenInfo of generatedTokens) {
      const envVar = `${tokenInfo.serviceName.toUpperCase().replace('-', '_')}_SERVICE_TOKEN`;
      console.log(`${envVar}="${tokenInfo.token}"`);
    }

    console.log('\n✅ Service token generation completed successfully!');
    console.log('\n📝 Next Steps:');
    console.log('1. Add the environment variables to your .env files');
    console.log('2. Update your service configurations to use service tokens');
    console.log('3. Restart your services');

  } catch (error) {
    console.error('❌ Service token generation failed:', error);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log('📤 Database connection closed');
  }
}

// Run the script
if (require.main === module) {
  generateServiceTokens();
}

module.exports = { generateServiceTokens, serviceConfigs }; 