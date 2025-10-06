const mongoose = require('mongoose');
const Resource = require('../src/models/Resource');
const config = require('../config/config');

async function updateDatabaseResource() {
  console.log('🔧 Updating test_database_operations resource...\n');
  
  try {
    // Connect to database
    await mongoose.connect(config.database.mongoUri, {
      dbName: config.database.dbName
    });
    console.log('✅ Connected to MongoDB');

    // Update the test_database_operations resource with correct endpoints
    const updatedResource = await Resource.findOneAndUpdate(
      { name: 'test_database_operations' },
      {
        $set: {
          endpoints: [
            {
              method: 'GET',
              path: '/:subaccountId/collections',
              description: 'List collections in database',
              requiredPermissions: ['read']
            },
            {
              method: 'POST', 
              path: '/:subaccountId/collections/:collection/find',
              description: 'Find documents in collection',
              requiredPermissions: ['read']
            },
            {
              method: 'POST',
              path: '/:subaccountId/collections/:collection/insertOne',
              description: 'Insert single document',
              requiredPermissions: ['write']
            },
            {
              method: 'POST',
              path: '/:subaccountId/collections/:collection/updateOne', 
              description: 'Update single document',
              requiredPermissions: ['write']
            },
            {
              method: 'POST',
              path: '/:subaccountId/collections/:collection/deleteOne',
              description: 'Delete single document', 
              requiredPermissions: ['delete']
            },
            {
              method: 'POST',
              path: '/:subaccountId/collections/:collection/aggregate',
              description: 'Run aggregation pipeline',
              requiredPermissions: ['read']
            },
            {
              method: 'POST',
              path: '/:subaccountId/collections/:collection/count',
              description: 'Count documents',
              requiredPermissions: ['read']
            }
          ],
          updatedAt: new Date()
        }
      },
      { new: true }
    );

    if (updatedResource) {
      console.log('✅ Updated resource: test_database_operations');
      console.log('📊 Endpoints updated:');
      updatedResource.endpoints.forEach(ep => {
        console.log(`   ${ep.method} ${ep.path} -> ${ep.requiredPermissions.join(', ')}`);
      });
    } else {
      console.log('❌ Resource test_database_operations not found');
    }

    await mongoose.disconnect();
    console.log('\n✅ Database connection closed');

  } catch (error) {
    console.error('❌ Error updating resource:', error.message);
    process.exit(1);
  }
}

// Run the update if this script is executed directly
if (require.main === module) {
  updateDatabaseResource();
}

module.exports = { updateDatabaseResource }; 