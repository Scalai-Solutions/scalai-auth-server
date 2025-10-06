# Bulk Permission Operations Implementation

## Overview
Added two new RBAC endpoints to enable resource permissions for all users of a subaccount at once.

## New Endpoints

### 1. Enable Resource Permissions for Subaccount
**Endpoint:** `POST /api/rbac/subaccounts/:subaccountId/resources/:resourceName/enable-permissions`

**Purpose:** Enable specific resource permissions for all users of a subaccount

**Authentication:** 
- JWT Token (Admin/Super Admin role required)
- Service Token validated against `TENANT_MANAGER_SERVICE_TOKEN` from .env with headers:
  - `X-Service-Token`: Must match `TENANT_MANAGER_SERVICE_TOKEN` from .env
  - `X-User-ID`: User ID performing the operation (optional)
  - `X-Service-Name`: Service name (e.g., 'tenant-manager', 'database-server')

**Request Body:**
```json
{
  "permissions": {
    "read": true,
    "write": true,
    "delete": false
  }
}
```

**Note:** Admin permission is always forced to `false` for security.

**Response:**
```json
{
  "success": true,
  "message": "Permissions granted to 3 users",
  "data": {
    "subaccountId": "68e0fd8a25cd2b009bd267e2",
    "resourceName": "database_operations",
    "permissions": {
      "read": true,
      "write": true,
      "delete": false,
      "admin": false
    },
    "totalUsers": 3,
    "successCount": 3,
    "errorCount": 0,
    "results": [...]
  }
}
```

### 2. Enable All Resource Permissions for Subaccount
**Endpoint:** `POST /api/rbac/subaccounts/:subaccountId/enable-all-permissions`

**Purpose:** Enable permissions for ALL resources for all users of a subaccount

**Authentication:** Same as above

**Request Body:**
```json
{
  "permissions": {
    "read": true,
    "write": true,
    "delete": false
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Permissions granted to 3 users for 5 resources",
  "data": {
    "subaccountId": "68e0fd8a25cd2b009bd267e2",
    "permissions": {
      "read": true,
      "write": true,
      "delete": false,
      "admin": false
    },
    "totalUsers": 3,
    "totalResources": 5,
    "totalOperations": 15,
    "successCount": 15,
    "errorCount": 0,
    "resourcesProcessed": [...]
  }
}
```

## Implementation Details

### Files Modified

1. **config/config.js**
   - Added `serviceTokens.tenantManager` configuration that reads from `TENANT_MANAGER_SERVICE_TOKEN` env variable

2. **src/middleware/serviceAuthMiddleware.js**
   - Added `authenticateTenantManagerToken()` middleware
   - Added `authenticateTokenOrTenantManager()` middleware
   - Service token is validated against `TENANT_MANAGER_SERVICE_TOKEN` environment variable

3. **src/middleware/rbacMiddleware.js**
   - Updated `requireRole()` to bypass role check for authenticated service tokens
   - Service token authentication is now treated as trusted and skips role hierarchy checks

4. **src/controllers/rbacController.js**
   - Added `enableResourcePermissionsForSubaccount()` method
   - Added `enableAllResourcePermissionsForSubaccount()` method

5. **src/routes/rbacRoutes.js**
   - Added route: `POST /subaccounts/:subaccountId/resources/:resourceName/enable-permissions`
   - Added route: `POST /subaccounts/:subaccountId/enable-all-permissions`
   - Routes use `authenticateTokenOrTenantManager` middleware for flexible authentication
   - Both routes require admin role and log sensitive operations

6. **docs/api-documentation.md**
   - Added comprehensive documentation for both endpoints
   - Added curl examples for testing

### Key Features

1. **Bulk Operations**: Process all users of a subaccount in a single request
2. **Error Handling**: Returns individual results and errors for each user
3. **Cache Invalidation**: Automatically invalidates permission cache for affected users
4. **Security**: 
   - Admin permission always forced to false
   - Only admin/super admin can access these endpoints
   - All operations are logged and audited
5. **Flexible Authentication**: Supports both JWT and Service Token authentication

### Security Considerations

- Admin permission cannot be granted through these endpoints (always false)
- Operations are logged as critical security events
- Requires admin or super_admin role
- All operations trigger audit logs
- Cache is invalidated for all affected users

### Usage Example

```bash
# Enable database operations permissions for all users in a subaccount
curl -X POST http://localhost:3001/api/rbac/subaccounts/68e0fd8a25cd2b009bd267e2/resources/database_operations/enable-permissions \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": {
      "read": true,
      "write": true,
      "delete": false
    }
  }'

# Or using service token (must match TENANT_MANAGER_SERVICE_TOKEN in .env)
curl -X POST http://localhost:3001/api/rbac/subaccounts/68e0fd8a25cd2b009bd267e2/resources/database_operations/enable-permissions \
  -H "X-Service-Token: your_tenant_manager_token_from_env" \
  -H "X-User-ID: user_id_performing_action" \
  -H "X-Service-Name: tenant-manager" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": {
      "read": true,
      "write": true,
      "delete": false
    }
  }'

# Enable all resource permissions
curl -X POST http://localhost:3001/api/rbac/subaccounts/68e0fd8a25cd2b009bd267e2/enable-all-permissions \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": {
      "read": true,
      "write": true,
      "delete": false
    }
  }'
```

## Environment Variables

Ensure `TENANT_MANAGER_SERVICE_TOKEN` is set in your .env file for service token authentication.

**Example .env entry:**
```bash
TENANT_MANAGER_SERVICE_TOKEN=your_secure_random_token_here_minimum_32_characters_long
```

**Generating a secure token:**
```bash
# Generate a random 64-character token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

The service token in the `X-Service-Token` header must exactly match this environment variable value for authentication to succeed.

## Testing

1. Start the auth server
2. Get an admin token by logging in with admin credentials
3. Use the curl examples above to test the endpoints
4. Verify permissions are granted to all users using `/api/rbac/permissions/user/:userId`

## Notes

- The endpoints use aggregation internally when needed for efficient database operations
- All operations are atomic per user (failures don't roll back successful operations)
- Failed operations are reported in the response without failing the entire request
- Cache invalidation is best-effort (failures are logged but don't fail the request)

