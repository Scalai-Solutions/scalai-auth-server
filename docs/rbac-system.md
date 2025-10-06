# ScalAI RBAC (Role-Based Access Control) System

## Overview

The ScalAI RBAC system provides comprehensive permission management across all microservices with composite role support, resource-based access control, and fine-grained permission management.

## Key Features

### 🔹 **Composite Roles**
- **Formula**: `Effective Role = Global Role + Subaccount Role`
- **Super Admin**: Full access to all resources across all subaccounts
- **Global Admin**: Access to all resources with `globalAdminAccess=true`
- **Subaccount-Specific Roles**: `viewer`, `editor`, `admin`, `owner` within specific subaccounts
- **Regular Users**: Permissions granted explicitly or inherited from subaccount membership

### 🔹 **Resource-Based Permissions**
- **Read**: View/query operations
- **Write**: Create/update operations  
- **Delete**: Delete operations
- **Admin**: Administrative operations (user management, configuration)

### 🔹 **Cross-Microservice Support**
- Centralized permission management in auth-server
- RBAC clients in tenant-manager and database-server
- Cached permission checks for performance
- Fail-closed security model

## Models

### 1. Resource Model (`src/models/Resource.js`)

Defines system resources that can be protected:

```javascript
{
  name: "database_operations",
  description: "Database queries and CRUD operations",
  type: "database_operations",
  service: "database-server",
  endpoints: [
    { 
      method: "POST", 
      path: "/api/database/:subaccountId/collections/:collection/find",
      requiredPermissions: ["read"]
    }
  ],
  defaultPermissions: {
    super_admin: { read: true, write: true, delete: true, admin: true },
    admin: { read: true, write: true, delete: true, admin: false },
    user: { read: false, write: false, delete: false, admin: false }
  },
  settings: {
    requiresSubaccount: true,
    globalAdminAccess: false
  }
}
```

### 2. Permission Model (`src/models/Permission.js`)

Manages user-resource-subaccount permission relationships:

```javascript
{
  userId: ObjectId,
  resourceId: ObjectId,
  subaccountId: ObjectId, // null for global permissions
  compositeRole: {
    globalRole: "user",
    subaccountRole: "editor", 
    effectiveRole: "editor" // Computed
  },
  permissions: {
    read: true,
    write: true,
    delete: false,
    admin: false
  },
  grantedBy: ObjectId,
  expiresAt: Date, // Optional expiration
  constraints: {
    allowedIPs: ["192.168.1.100"],
    allowedHours: { start: 9, end: 17 }
  }
}
```

## API Endpoints

### Resource Management (Super Admin Only)

#### Create Resource with Endpoints

```bash
# Create a resource with multiple endpoints
curl -X POST http://localhost:3001/api/rbac/resources \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "custom_operations",
    "description": "Custom API operations",
    "type": "custom",
    "service": "custom-service",
    "endpoints": [
      {
        "method": "GET",
        "path": "/api/custom/items",
        "description": "List all items",
        "requiredPermissions": ["read"]
      },
      {
        "method": "POST",
        "path": "/api/custom/items",
        "description": "Create a new item",
        "requiredPermissions": ["write"]
      },
      {
        "method": "PUT",
        "path": "/api/custom/items/:id",
        "description": "Update an item",
        "requiredPermissions": ["write"]
      },
      {
        "method": "DELETE",
        "path": "/api/custom/items/:id",
        "description": "Delete an item",
        "requiredPermissions": ["delete"]
      }
    ],
    "defaultPermissions": {
      "super_admin": {
        "read": true,
        "write": true,
        "delete": true,
        "admin": true
      },
      "admin": {
        "read": true,
        "write": true,
        "delete": true,
        "admin": false
      },
      "user": {
        "read": false,
        "write": false,
        "delete": false,
        "admin": false
      }
    },
    "settings": {
      "requiresSubaccount": true,
      "globalAdminAccess": false,
      "rateLimits": {
        "perUser": {
          "requests": 100,
          "windowMs": 60000
        },
        "perSubaccount": {
          "requests": 1000,
          "windowMs": 60000
        }
      }
    }
  }'
```

**Example: Database Operations Resource**
```bash
curl -X POST http://localhost:3001/api/rbac/resources \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "database_operations",
    "description": "Database queries and CRUD operations",
    "type": "database_operations",
    "service": "database-server",
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/find",
        "description": "Query documents from a collection",
        "requiredPermissions": ["read"]
      },
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/insertOne",
        "description": "Insert a single document",
        "requiredPermissions": ["write"]
      },
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/updateMany",
        "description": "Update multiple documents",
        "requiredPermissions": ["write"]
      },
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/deleteMany",
        "description": "Delete multiple documents",
        "requiredPermissions": ["delete"]
      },
      {
        "method": "GET",
        "path": "/api/database/:subaccountId/stats",
        "description": "Get database statistics",
        "requiredPermissions": ["read"]
      }
    ],
    "defaultPermissions": {
      "super_admin": {
        "read": true,
        "write": true,
        "delete": true,
        "admin": true
      },
      "admin": {
        "read": true,
        "write": true,
        "delete": false,
        "admin": false
      },
      "user": {
        "read": false,
        "write": false,
        "delete": false,
        "admin": false
      }
    },
    "settings": {
      "requiresSubaccount": true,
      "globalAdminAccess": false
    }
  }'
```

**Example: Subaccount Management Resource**
```bash
curl -X POST http://localhost:3001/api/rbac/resources \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "subaccount_management",
    "description": "Subaccount creation and management",
    "type": "subaccount",
    "service": "tenant-manager",
    "endpoints": [
      {
        "method": "GET",
        "path": "/api/subaccounts",
        "description": "List all subaccounts for user",
        "requiredPermissions": ["read"]
      },
      {
        "method": "POST",
        "path": "/api/subaccounts",
        "description": "Create a new subaccount",
        "requiredPermissions": ["write"]
      },
      {
        "method": "PUT",
        "path": "/api/subaccounts/:subaccountId",
        "description": "Update subaccount details",
        "requiredPermissions": ["admin"]
      },
      {
        "method": "DELETE",
        "path": "/api/subaccounts/:subaccountId",
        "description": "Delete a subaccount",
        "requiredPermissions": ["delete"]
      },
      {
        "method": "POST",
        "path": "/api/subaccounts/:subaccountId/members",
        "description": "Add member to subaccount",
        "requiredPermissions": ["admin"]
      }
    ],
    "defaultPermissions": {
      "super_admin": {
        "read": true,
        "write": true,
        "delete": true,
        "admin": true
      },
      "admin": {
        "read": true,
        "write": true,
        "delete": false,
        "admin": true
      },
      "user": {
        "read": true,
        "write": true,
        "delete": false,
        "admin": false
      }
    },
    "settings": {
      "requiresSubaccount": false,
      "globalAdminAccess": true
    }
  }'
```

#### Update Resource - Add New Endpoints
```bash
# Add new endpoints to an existing resource (merges with existing, no duplicates)
# First, get the resource ID
curl -X GET "http://localhost:3001/api/rbac/resources?name=database_operations" \
  -H "Authorization: Bearer <admin_token>"

# Then update with new endpoints - these will be ADDED to existing endpoints
curl -X PUT http://localhost:3001/api/rbac/resources/<resource_id> \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/aggregate",
        "description": "Aggregate documents from a collection",
        "requiredPermissions": ["read"]
      },
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/countDocuments",
        "description": "Count documents in a collection",
        "requiredPermissions": ["read"]
      }
    ]
  }'
```

**Note:** The update endpoint **merges** new endpoints with existing ones. If an endpoint with the same `method` and `path` already exists, it will be updated. Otherwise, it will be added.

**Example: Update existing endpoint**
```bash
# This will UPDATE the description/permissions of an existing endpoint
curl -X PUT http://localhost:3001/api/rbac/resources/<resource_id> \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/find",
        "description": "Query documents with advanced filters (UPDATED)",
        "requiredPermissions": ["read", "admin"]
      }
    ]
  }'
```

**Example: Update multiple fields**
```bash
# Update description, settings, and add new endpoints at once
curl -X PUT http://localhost:3001/api/rbac/resources/<resource_id> \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Enhanced database operations with advanced features",
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/database/:subaccountId/collections/:collection/bulkWrite",
        "description": "Perform bulk write operations",
        "requiredPermissions": ["write"]
      }
    ],
    "settings": {
      "requiresSubaccount": true,
      "globalAdminAccess": false,
      "rateLimits": {
        "perUser": {
          "requests": 200,
          "windowMs": 60000
        }
      }
    }
  }'
```

#### How Endpoint Merging Works

When you update a resource with new endpoints, the system uses **smart merging**:

**Duplicate Detection:**
- Endpoints are identified by their `method` + `path` combination
- Example: `POST:/api/database/:subaccountId/collections/:collection/find`

**Merging Behavior:**

| Scenario | Behavior | Example |
|----------|----------|---------|
| **New endpoint** | Added to resource | Resource has GET /items, you add POST /items → Both exist |
| **Existing endpoint** | Updated (replaced) | Resource has POST /items with "read" permission, you update with "write" permission → Permission changes |
| **Same method, different path** | Both kept | Resource has POST /items, you add POST /users → Both exist |
| **Different method, same path** | Both kept | Resource has GET /items, you add POST /items → Both exist |

**Example Flow:**

```javascript
// Initial resource has these endpoints:
[
  { method: "GET", path: "/api/items", description: "List items", requiredPermissions: ["read"] },
  { method: "POST", path: "/api/items", description: "Create item", requiredPermissions: ["write"] }
]

// You send an update with:
[
  { method: "POST", path: "/api/items", description: "Create item (Updated)", requiredPermissions: ["write", "admin"] },
  { method: "DELETE", path: "/api/items/:id", description: "Delete item", requiredPermissions: ["delete"] }
]

// Result will be:
[
  { method: "GET", path: "/api/items", description: "List items", requiredPermissions: ["read"] },  // Kept
  { method: "POST", path: "/api/items", description: "Create item (Updated)", requiredPermissions: ["write", "admin"] },  // Updated
  { method: "DELETE", path: "/api/items/:id", description: "Delete item", requiredPermissions: ["delete"] }  // Added
]
```

**Benefits:**
- ✅ No accidental deletion of existing endpoints
- ✅ Easy to add new endpoints without fetching current ones
- ✅ Can update specific endpoints without affecting others
- ✅ Automatic deduplication by method+path

#### List Resources
```bash
# List all resources
curl -X GET http://localhost:3001/api/rbac/resources \
  -H "Authorization: Bearer <admin_token>"

# Filter by service
curl -X GET "http://localhost:3001/api/rbac/resources?service=database-server" \
  -H "Authorization: Bearer <admin_token>"

# Filter by type
curl -X GET "http://localhost:3001/api/rbac/resources?type=database_operations" \
  -H "Authorization: Bearer <admin_token>"

# Filter by service and type
curl -X GET "http://localhost:3001/api/rbac/resources?service=database-server&type=database_operations" \
  -H "Authorization: Bearer <admin_token>"
```

#### Resolve Resource by Endpoint
```bash
# Check which resource controls a specific endpoint
curl -X GET "http://localhost:3001/api/rbac/resources/resolve?method=POST&path=/api/database/12345/collections/users/find&service=database-server" \
  -H "Authorization: Bearer <token>"
```

### Permission Management (Admin and Above)

```bash
# Grant permission
POST /api/rbac/permissions/grant
Authorization: Bearer <admin_token>
{
  "userId": "user_id_here",
  "resourceName": "database_operations",
  "permissions": {
    "read": true,
    "write": true,
    "delete": false,
    "admin": false
  },
  "subaccountId": "subaccount_id_here", // Optional
  "expiresAt": "2024-12-31T23:59:59Z", // Optional
  "constraints": {
    "allowedIPs": ["192.168.1.100"],
    "dailyUsageLimit": 100
  }
}

# Revoke permission
POST /api/rbac/permissions/revoke
Authorization: Bearer <admin_token>
{
  "userId": "user_id_here",
  "resourceName": "database_operations",
  "subaccountId": "subaccount_id_here" // Optional
}

# Check user permissions
GET /api/rbac/permissions/check?userId=...&resourceName=...&subaccountId=...
Authorization: Bearer <admin_token>

# List user permissions
GET /api/rbac/permissions/user/{userId}?subaccountId=...&resourceType=...
Authorization: Bearer <admin_token>
```

### System Overview

```bash
# Get RBAC system overview
GET /api/rbac/overview
Authorization: Bearer <admin_token>
```

## Middleware Integration

### Auth Server (Direct RBAC)

```javascript
const { requirePermission, requireRole } = require('./middleware/rbacMiddleware');

// Protect routes with specific permissions
router.get('/api/users', 
  requirePermission('user_management', 'read'),
  UserController.listUsers
);

router.post('/api/users/:userId/role',
  requirePermission('user_management', 'admin'),
  UserController.changeRole
);

// Protect routes with role requirements
router.delete('/api/system/reset',
  requireRole('super_admin'),
  SystemController.reset
);
```

### Tenant Manager (RBAC Client)

```javascript
const { requirePermission, tenantPermissions } = require('./middleware/rbacClient');

// Use pre-built permission checks
router.get('/api/subaccounts',
  tenantPermissions.subaccounts.read,
  SubaccountController.getUserSubaccounts
);

router.post('/api/subaccounts',
  tenantPermissions.subaccounts.write,
  SubaccountController.createSubaccount
);

// Custom permission checks
router.put('/api/subaccounts/:subaccountId',
  requirePermission('subaccount_management', 'admin', {
    extractSubaccountId: req => req.params.subaccountId
  }),
  SubaccountController.updateSubaccount
);
```

### Database Server (RBAC Client)

```javascript
const { requirePermission, databasePermissions } = require('./middleware/rbacClient');

// Use pre-built permission checks
router.post('/api/database/:subaccountId/collections/:collection/find',
  databasePermissions.read,
  DatabaseController.find
);

router.post('/api/database/:subaccountId/collections/:collection/insertOne',
  databasePermissions.write,
  DatabaseController.insertOne
);

router.post('/api/database/:subaccountId/collections/:collection/deleteMany',
  databasePermissions.delete,
  DatabaseController.deleteMany
);
```

## Permission Hierarchy

### Global Roles
```
super_admin > admin > user
```

### Subaccount Roles
```
owner > admin > editor > viewer
```

### Effective Role Calculation
```javascript
if (globalRole === 'super_admin') {
  effectiveRole = 'super_admin';
} else if (globalRole === 'admin') {
  effectiveRole = 'admin';
} else if (subaccountRole) {
  effectiveRole = subaccountRole; // viewer, editor, admin, owner
} else {
  effectiveRole = globalRole; // user
}
```

## Security Features

### 🔒 **Access Control**
- **Fail-Closed**: Deny access on errors or missing permissions
- **Token Validation**: All requests require valid JWT tokens with role information
- **IP Restrictions**: Optional IP-based access controls
- **Time Restrictions**: Optional time-based access controls

### 🔍 **Audit & Monitoring**
- **Permission Checks**: All checks logged with detailed context
- **Usage Tracking**: Track permission usage patterns
- **Security Events**: Failed access attempts logged as security events
- **Cache Management**: Efficient caching with automatic invalidation

### ⚡ **Performance**
- **Caching**: 5-minute cache for permission checks
- **Efficient Queries**: Optimized database indexes
- **Batch Operations**: Support for bulk permission operations

## Setup & Initialization

### 1. Initialize RBAC Resources
```bash
cd scalai-auth-server
npm run init-rbac
```

### 2. Add Dependencies to Microservices
```bash
# Tenant Manager
cd scalai-tenant-manager
npm install axios

# Database Server  
cd scalai-database-server
npm install axios
```

### 3. Apply RBAC Middleware to Routes
Replace existing authentication middleware with RBAC middleware in each microservice.

## Usage Examples

### Example 1: Protect Subaccount Operations
```javascript
// Before (simple auth)
router.get('/api/subaccounts', authenticateToken, getSubaccounts);

// After (RBAC)
router.get('/api/subaccounts', 
  requirePermission('subaccount_management', 'read'),
  getSubaccounts
);
```

### Example 2: Grant Database Permissions to User
```bash
curl -X POST 'https://auth-server/api/rbac/permissions/grant' \
-H 'Authorization: Bearer <admin_token>' \
-H 'Content-Type: application/json' \
-d '{
  "userId": "user_id_here",
  "resourceName": "database_operations", 
  "permissions": {
    "read": true,
    "write": true,
    "delete": false,
    "admin": false
  },
  "subaccountId": "subaccount_id_here"
}'
```

### Example 3: Check User Permissions
```bash
curl 'https://auth-server/api/rbac/permissions/check?userId=...&resourceName=database_operations&subaccountId=...' \
-H 'Authorization: Bearer <admin_token>'
```

## Role Scenarios

### Scenario 1: Super Admin
- **Global Role**: `super_admin`
- **Effective Role**: `super_admin` 
- **Access**: Full access to ALL resources across ALL subaccounts

### Scenario 2: Global Admin
- **Global Role**: `admin`
- **Effective Role**: `admin`
- **Access**: Full access to resources with `globalAdminAccess=true`

### Scenario 3: Subaccount Owner
- **Global Role**: `user`
- **Subaccount Role**: `owner`
- **Effective Role**: `owner`
- **Access**: Full access within specific subaccount

### Scenario 4: Regular User with Grants
- **Global Role**: `user`
- **Subaccount Role**: `editor`
- **Explicit Grants**: Read/write to specific resources
- **Effective Role**: `editor` (for subaccount) + explicit grants

## Migration Guide

### From Current System to RBAC

1. **Initialize RBAC resources**: `npm run init-rbac`
2. **Replace middleware**: Update route middleware to use RBAC
3. **Grant permissions**: Set up permissions for existing users
4. **Test thoroughly**: Verify all endpoints work with new permissions
5. **Monitor**: Watch audit logs for permission denials

The RBAC system is now ready for production deployment! 🚀 