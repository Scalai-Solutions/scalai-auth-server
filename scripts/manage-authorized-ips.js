#!/usr/bin/env node

const mongoose = require('mongoose');
const config = require('../config/config');
const AuthorizedIP = require('../src/models/AuthorizedIP');
const User = require('../src/models/User');

// Connect to database
async function connectDB() {
  try {
    await mongoose.connect(config.database.mongoUri, {
      dbName: config.database.dbName
    });
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error.message);
    process.exit(1);
  }
}

// Add authorized IP
async function addAuthorizedIP(ipAddress, description, permissions = {}, authorizedByEmail = null) {
  try {
    // Find super admin user to authorize this IP
    let authorizedBy;
    if (authorizedByEmail) {
      authorizedBy = await User.findOne({ email: authorizedByEmail, role: 'super_admin' });
      if (!authorizedBy) {
        throw new Error(`Super admin user not found with email: ${authorizedByEmail}`);
      }
    } else {
      // Find any super admin
      authorizedBy = await User.findOne({ role: 'super_admin' });
      if (!authorizedBy) {
        throw new Error('No super admin users found. Create a super admin first.');
      }
    }

    const result = await AuthorizedIP.addAuthorizedIP({
      ipAddress,
      description,
      permissions: {
        changeUserRole: permissions.changeUserRole || false,
        createSuperAdmin: permissions.createSuperAdmin || false,
        systemMaintenance: permissions.systemMaintenance || false
      },
      expiresAt: permissions.expiresAt || null,
      dailyUsageLimit: permissions.dailyUsageLimit || 10
    }, authorizedBy._id);

    if (result.success) {
      console.log('✅ Authorized IP added successfully:');
      console.log('   IP:', result.authorizedIP.ipAddress);
      console.log('   Description:', result.authorizedIP.description);
      console.log('   Permissions:', result.authorizedIP.permissions);
      console.log('   Authorized by:', authorizedBy.email);
      console.log('   Daily usage limit:', result.authorizedIP.dailyUsageLimit);
    } else {
      console.error('❌ Failed to add authorized IP:', result.error);
    }
  } catch (error) {
    console.error('❌ Error adding authorized IP:', error.message);
  }
}

// List authorized IPs
async function listAuthorizedIPs() {
  try {
    const authorizedIPs = await AuthorizedIP.find({ isActive: true })
      .populate('authorizedBy', 'email firstName lastName')
      .sort({ createdAt: -1 });

    console.log('\n📋 Authorized IPs:');
    console.log('==================');
    
    if (authorizedIPs.length === 0) {
      console.log('No authorized IPs found.');
      return;
    }

    authorizedIPs.forEach((ip, index) => {
      console.log(`\n${index + 1}. IP: ${ip.ipAddress}`);
      console.log(`   Description: ${ip.description}`);
      console.log(`   Permissions:`);
      console.log(`     - Change User Role: ${ip.permissions.changeUserRole ? '✅' : '❌'}`);
      console.log(`     - Create Super Admin: ${ip.permissions.createSuperAdmin ? '✅' : '❌'}`);
      console.log(`     - System Maintenance: ${ip.permissions.systemMaintenance ? '✅' : '❌'}`);
      console.log(`   Authorized by: ${ip.authorizedBy.email}`);
      console.log(`   Daily usage: ${ip.dailyUsageCount}/${ip.dailyUsageLimit}`);
      console.log(`   Total usage: ${ip.usageCount}`);
      console.log(`   Last used: ${ip.lastUsed || 'Never'}`);
      console.log(`   Expires: ${ip.expiresAt || 'Never'}`);
      console.log(`   Created: ${ip.createdAt}`);
    });
  } catch (error) {
    console.error('❌ Error listing authorized IPs:', error.message);
  }
}

// Remove authorized IP
async function removeAuthorizedIP(ipAddress) {
  try {
    const result = await AuthorizedIP.findOneAndUpdate(
      { ipAddress },
      { isActive: false },
      { new: true }
    );

    if (result) {
      console.log(`✅ Authorized IP ${ipAddress} has been deactivated`);
    } else {
      console.log(`❌ Authorized IP ${ipAddress} not found`);
    }
  } catch (error) {
    console.error('❌ Error removing authorized IP:', error.message);
  }
}

// Main CLI function
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  await connectDB();

  switch (command) {
    case 'add':
      if (args.length < 3) {
        console.log('Usage: npm run manage-ips add <ip> <description> [permissions] [authorizedByEmail]');
        console.log('Example: npm run manage-ips add "192.168.1.100" "Admin workstation" "changeUserRole=true" "admin@example.com"');
        process.exit(1);
      }
      
      const ipAddress = args[1];
      const description = args[2];
      const permissionsStr = args[3] || '';
      const authorizedByEmail = args[4] || null;
      
      // Parse permissions
      const permissions = {};
      if (permissionsStr) {
        permissionsStr.split(',').forEach(perm => {
          const [key, value] = perm.split('=');
          if (key && value) {
            permissions[key.trim()] = value.trim() === 'true';
          }
        });
      }
      
      await addAuthorizedIP(ipAddress, description, permissions, authorizedByEmail);
      break;

    case 'list':
      await listAuthorizedIPs();
      break;

    case 'remove':
      if (args.length < 2) {
        console.log('Usage: npm run manage-ips remove <ip>');
        process.exit(1);
      }
      await removeAuthorizedIP(args[1]);
      break;

    case 'add-localhost':
      // Quick command to add localhost for development
      await addAuthorizedIP('localhost', 'Development localhost', {
        changeUserRole: true,
        createSuperAdmin: true,
        systemMaintenance: true
      });
      break;

    default:
      console.log('ScalAI Auth Server - Authorized IP Management');
      console.log('=============================================');
      console.log('');
      console.log('Commands:');
      console.log('  add <ip> <description> [permissions] [authorizedByEmail]  - Add authorized IP');
      console.log('  list                                                      - List authorized IPs');
      console.log('  remove <ip>                                              - Remove authorized IP');
      console.log('  add-localhost                                            - Add localhost for development');
      console.log('');
      console.log('Examples:');
      console.log('  npm run manage-ips add "192.168.1.100" "Admin workstation" "changeUserRole=true"');
      console.log('  npm run manage-ips add-localhost');
      console.log('  npm run manage-ips list');
      console.log('  npm run manage-ips remove "192.168.1.100"');
      break;
  }

  await mongoose.disconnect();
  console.log('\n🔒 Database connection closed');
}

main(); 