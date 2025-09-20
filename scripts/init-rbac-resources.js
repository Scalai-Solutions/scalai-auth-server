#!/usr/bin/env node

const mongoose = require('mongoose');
const config = require('../config/config');
const Resource = require('../src/models/Resource');
const User = require('../src/models/User');

// Default resources for the ScalAI system
const defaultResources = [
  // Auth Server Resources
  {
    name: 'user_management',
    description: 'User CRUD operations and role management',
    type: 'user_management',
    service: 'auth-server',
    endpoints: [
      { method: 'GET', path: '/api/auth/profile', description: 'Get user profile', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/auth/admin/change-user-role', description: 'Change user role', requiredPermissions: ['admin'] },
      { method: 'GET', path: '/api/auth/sessions', description: 'Get user sessions', requiredPermissions: ['read'] },
      { method: 'DELETE', path: '/api/auth/sessions/:sessionId', description: 'Revoke session', requiredPermissions: ['write'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: true },
      user: { read: true, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: false,
      globalAdminAccess: true
    }
  },
  
  // Tenant Manager Resources
  {
    name: 'subaccount_management',
    description: 'Subaccount creation, configuration, and management',
    type: 'subaccount',
    service: 'tenant-manager',
    endpoints: [
      { method: 'GET', path: '/api/subaccounts', description: 'List user subaccounts', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/subaccounts', description: 'Create subaccount', requiredPermissions: ['write'] },
      { method: 'GET', path: '/api/subaccounts/:subaccountId', description: 'Get subaccount details', requiredPermissions: ['read'] },
      { method: 'PUT', path: '/api/subaccounts/:subaccountId', description: 'Update subaccount', requiredPermissions: ['admin'] },
      { method: 'DELETE', path: '/api/subaccounts/:subaccountId', description: 'Delete subaccount', requiredPermissions: ['admin'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: true },
      user: { read: true, write: true, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: true,
      globalAdminAccess: true
    }
  },
  
  {
    name: 'user_subaccount_management',
    description: 'User-subaccount relationship management',
    type: 'user_management',
    service: 'tenant-manager',
    endpoints: [
      { method: 'GET', path: '/api/users/:subaccountId', description: 'Get subaccount users', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/users/invite', description: 'Invite user to subaccount', requiredPermissions: ['admin'] },
      { method: 'PUT', path: '/api/users/:userId/permissions', description: 'Update user permissions', requiredPermissions: ['admin'] },
      { method: 'DELETE', path: '/api/users/:userId', description: 'Remove user from subaccount', requiredPermissions: ['admin'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: true },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: true,
      globalAdminAccess: true
    }
  },
  
  // Database Server Resources
  {
    name: 'database_operations',
    description: 'Database queries and CRUD operations',
    type: 'database_operations',
    service: 'database-server',
    endpoints: [
      { method: 'GET', path: '/api/database/:subaccountId/collections', description: 'List collections', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/find', description: 'Find documents', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/insertOne', description: 'Insert document', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/insertMany', description: 'Insert multiple documents', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/updateOne', description: 'Update document', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/updateMany', description: 'Update multiple documents', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/deleteOne', description: 'Delete document', requiredPermissions: ['delete'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/deleteMany', description: 'Delete multiple documents', requiredPermissions: ['delete'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/aggregate', description: 'Aggregation pipeline', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/count', description: 'Count documents', requiredPermissions: ['read'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: false },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: true,
      globalAdminAccess: false, // Database operations should respect subaccount permissions
      rateLimits: {
        perUser: { requests: 200, windowMs: 60000 },
        perSubaccount: { requests: 1000, windowMs: 60000 }
      }
    }
  },
  
  {
    name: 'llm_operations',
    description: 'LLM API calls and AI operations',
    type: 'llm_operations',
    service: 'database-server',
    endpoints: [
      { method: 'POST', path: '/api/llm/query', description: 'Execute LLM query', requiredPermissions: ['write'] },
      { method: 'GET', path: '/api/llm/models', description: 'List available models', requiredPermissions: ['read'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: false, admin: false },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: true,
      globalAdminAccess: false,
      rateLimits: {
        perUser: { requests: 50, windowMs: 60000 },
        perSubaccount: { requests: 200, windowMs: 60000 }
      }
    }
  },
  
  // System Administration Resources
  {
    name: 'system_admin',
    description: 'System administration and configuration',
    type: 'system_admin',
    service: 'shared',
    endpoints: [
      { method: '*', path: '/api/admin/*', description: 'All admin operations', requiredPermissions: ['admin'] },
      { method: 'GET', path: '/api/rbac/overview', description: 'RBAC system overview', requiredPermissions: ['admin'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: true },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: false,
      globalAdminAccess: true
    }
  },
  
  {
    name: 'audit_logs',
    description: 'Audit log access and analysis',
    type: 'audit_logs',
    service: 'shared',
    endpoints: [
      { method: 'GET', path: '/api/audit/logs', description: 'Access audit logs', requiredPermissions: ['read'] },
      { method: 'GET', path: '/api/audit/analytics', description: 'Audit analytics', requiredPermissions: ['admin'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: false, delete: false, admin: true },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: false,
      globalAdminAccess: true
    }
  },
  
  // Database Server Resources - Agent Resource for simplified CRUD operations
  {
    name: 'agent',
    description: 'Agent database CRUD operations - simplified database access for AI agents',
    type: 'database_operations',
    service: 'database-server',
    endpoints: [
      { method: 'GET', path: '/api/database/:subaccountId/collections', description: 'List collections for agent', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/find', description: 'Agent find documents', requiredPermissions: ['read'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/insertOne', description: 'Agent insert document', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/updateOne', description: 'Agent update document', requiredPermissions: ['write'] },
      { method: 'POST', path: '/api/database/:subaccountId/collections/:collection/deleteOne', description: 'Agent delete document', requiredPermissions: ['delete'] }
    ],
    defaultPermissions: {
      super_admin: { read: true, write: true, delete: true, admin: true },
      admin: { read: true, write: true, delete: true, admin: false },
      user: { read: false, write: false, delete: false, admin: false }
    },
    settings: {
      requiresSubaccount: true,
      globalAdminAccess: false, // Agents should respect subaccount permissions strictly
      rateLimits: {
        perUser: { requests: 100, windowMs: 60000 },
        perSubaccount: { requests: 500, windowMs: 60000 }
      }
    }
  }
];

async function initializeRBACResources() {
  console.log('🔧 Initializing RBAC resources...\n');
  
  try {
    // Connect to database
    await mongoose.connect(config.database.mongoUri, {
      dbName: config.database.dbName
    });
    console.log('✅ Connected to MongoDB');

    // Find super admin to use as creator
    const superAdmin = await User.findOne({ role: 'super_admin' });
    if (!superAdmin) {
      console.log('❌ No super admin found. Please create a super admin first.');
      process.exit(1);
    }
    console.log('✅ Using super admin as creator:', superAdmin.email);

    let createdCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;

    for (const resourceData of defaultResources) {
      try {
        const existingResource = await Resource.findOne({ name: resourceData.name });
        
        if (existingResource) {
          // Update existing resource
          await Resource.findOneAndUpdate(
            { name: resourceData.name },
            {
              ...resourceData,
              createdBy: existingResource.createdBy, // Keep original creator
              updatedAt: new Date()
            }
          );
          console.log(`🔄 Updated resource: ${resourceData.name}`);
          updatedCount++;
        } else {
          // Create new resource
          const resource = new Resource({
            ...resourceData,
            createdBy: superAdmin._id
          });
          await resource.save();
          console.log(`✅ Created resource: ${resourceData.name}`);
          createdCount++;
        }
      } catch (error) {
        console.log(`❌ Failed to process resource ${resourceData.name}:`, error.message);
        skippedCount++;
      }
    }

    console.log('\n📊 RBAC Initialization Summary:');
    console.log(`   Created: ${createdCount} resources`);
    console.log(`   Updated: ${updatedCount} resources`);
    console.log(`   Skipped: ${skippedCount} resources`);
    console.log(`   Total: ${defaultResources.length} resources processed`);

    console.log('\n🎉 RBAC system initialized successfully!');
    console.log('\n📚 Next steps:');
    console.log('1. Use RBAC middleware in your microservices');
    console.log('2. Grant permissions to users as needed');
    console.log('3. Monitor permission usage through audit logs');

  } catch (error) {
    console.error('❌ RBAC initialization failed:', error.message);
    console.error(error.stack);
  } finally {
    await mongoose.disconnect();
    console.log('\n🔒 Database connection closed');
  }
}

// Main execution
initializeRBACResources(); 