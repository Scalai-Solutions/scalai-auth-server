# Troubleshooting Guide

## Common Issues and Solutions

### 1. Server Startup Issues

#### Issue: "Missing required environment variable"
```bash
Error: Missing required environment variable: JWT_SECRET
```

**Solution:**
```bash
# Check if .env file exists
ls -la .env

# Create .env file if missing
cp .env.example .env

# Ensure required variables are set
JWT_SECRET=your_jwt_secret_here
JWT_REFRESH_SECRET=your_refresh_secret_here
MONGODB_URI=your_mongodb_connection_string
```

#### Issue: "Port already in use"
```bash
Error: listen EADDRINUSE: address already in use :::3001
```

**Solution:**
```bash
# Find process using port 3001
sudo lsof -i :3001
# or
netstat -tulpn | grep 3001

# Kill the process
sudo kill -9 <PID>

# Or use a different port
PORT=3002 npm start
```

#### Issue: "MongoDB connection failed"
```bash
Error: MongoDB connection failed: bad auth : authentication failed
```

**Solutions:**
1. **Check MongoDB URI format:**
   ```bash
   # Correct format
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database
   
   # URL encode special characters
   # @ becomes %40, : becomes %3A, etc.
   MONGODB_URI=mongodb+srv://user:p%40ssw0rd@cluster.mongodb.net/db
   ```

2. **Verify credentials:**
   ```bash
   # Test connection with MongoDB Compass or CLI
   mongo "mongodb+srv://cluster.mongodb.net/test" --username your_username
   ```

3. **Check IP whitelist:**
   - Add your server's IP to MongoDB Atlas whitelist
   - For development, you can use 0.0.0.0/0 (not recommended for production)

### 2. Authentication Issues

#### Issue: "Invalid or expired token"
```json
{
  "success": false,
  "message": "Invalid or expired token"
}
```

**Solutions:**
1. **Check token format:**
   ```bash
   # Correct header format
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

2. **Verify JWT secret:**
   ```bash
   # Ensure JWT_SECRET matches between token creation and verification
   echo $JWT_SECRET
   ```

3. **Check token expiration:**
   ```javascript
   // Decode token to check expiration (client-side debugging)
   const jwt = require('jsonwebtoken');
   const decoded = jwt.decode(token);
   console.log('Token expires:', new Date(decoded.exp * 1000));
   ```

#### Issue: "User not found or inactive"
```json
{
  "success": false,
  "message": "User not found or inactive"
}
```

**Solutions:**
1. **Check user status in database:**
   ```javascript
   // MongoDB query
   db.users.findOne({ email: "user@example.com" });
   ```

2. **Verify user is active:**
   ```javascript
   // Update user status
   db.users.updateOne(
     { email: "user@example.com" },
     { $set: { isActive: true } }
   );
   ```

### 3. Database Issues

#### Issue: Duplicate key error
```bash
E11000 duplicate key error collection: scalai_auth.users index: email_1
```

**Solution:**
```javascript
// Check for existing user before creation
const existingUser = await User.findOne({ email: userData.email });
if (existingUser) {
  return res.status(400).json({
    success: false,
    message: 'User with this email already exists'
  });
}
```

#### Issue: Slow database queries
```bash
Query took 5000ms to execute
```

**Solutions:**
1. **Add database indexes:**
   ```javascript
   // Create indexes for frequently queried fields
   db.users.createIndex({ email: 1 });
   db.refreshtokens.createIndex({ token: 1 });
   db.refreshtokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
   ```

2. **Optimize queries:**
   ```javascript
   // Use projection to limit returned fields
   const user = await User.findById(id).select('email firstName lastName');
   
   // Use lean() for read-only operations
   const users = await User.find({}).lean();
   ```

#### Issue: Connection pool exhausted
```bash
Error: connection pool exhausted
```

**Solution:**
```javascript
// Increase connection pool size
mongoose.connect(uri, {
  maxPoolSize: 20,        // Increase from default 10
  minPoolSize: 5,         // Maintain minimum connections
  maxIdleTimeMS: 30000,   // Close connections after 30 seconds of inactivity
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
});
```

### 4. Performance Issues

#### Issue: High memory usage
```bash
Memory usage: 512MB (growing continuously)
```

**Solutions:**
1. **Check for memory leaks:**
   ```bash
   # Monitor memory usage
   node --inspect src/server.js
   # Open Chrome DevTools to analyze memory
   ```

2. **Optimize database connections:**
   ```javascript
   // Close unused connections
   mongoose.connection.close();
   
   // Use connection pooling
   const options = {
     maxPoolSize: 10,
     bufferMaxEntries: 0
   };
   ```

3. **Implement caching:**
   ```javascript
   // Cache frequently accessed data
   const NodeCache = require('node-cache');
   const cache = new NodeCache({ stdTTL: 600 }); // 10 minutes
   
   // Cache user data
   const cachedUser = cache.get(`user_${userId}`);
   if (!cachedUser) {
     const user = await User.findById(userId);
     cache.set(`user_${userId}`, user);
   }
   ```

#### Issue: Slow response times
```bash
Average response time: 3000ms
```

**Solutions:**
1. **Add response time monitoring:**
   ```javascript
   const responseTime = require('response-time');
   app.use(responseTime((req, res, time) => {
     if (time > 1000) {
       console.warn(`Slow request: ${req.method} ${req.url} - ${time}ms`);
     }
   }));
   ```

2. **Optimize middleware order:**
   ```javascript
   // Put lightweight middleware first
   app.use(helmet());
   app.use(cors());
   app.use(express.json());
   // Put heavy middleware last
   app.use(rateLimiter);
   ```

### 5. Security Issues

#### Issue: "Token security validation failed"
```json
{
  "success": false,
  "message": "Token security validation failed. Please login again."
}
```

**Cause:** Refresh token used from different IP address.

**Solutions:**
1. **For development (disable IP validation):**
   ```javascript
   // Temporarily disable IP validation in development
   if (process.env.NODE_ENV === 'development') {
     // Skip IP validation
   } else {
     // Perform IP validation
   }
   ```

2. **For production (investigate security):**
   ```bash
   # Check logs for security alerts
   grep "token_ip_mismatch" logs/combined.log
   
   # Review user's login patterns
   db.refreshtokens.find({ user: ObjectId("user_id") }).sort({ createdAt: -1 });
   ```

#### Issue: Rate limiting too aggressive
```json
{
  "success": false,
  "message": "Too many attempts. Please try again later."
}
```

**Solutions:**
1. **Adjust rate limits:**
   ```javascript
   // Increase limits for development
   const rateLimits = {
     login: process.env.NODE_ENV === 'development' ? 10 : 5,
     register: process.env.NODE_ENV === 'development' ? 5 : 3
   };
   ```

2. **Clear rate limit data:**
   ```javascript
   // For in-memory rate limiter, restart server
   // For Redis-based limiter:
   redis.flushdb();
   ```

### 6. Validation Issues

#### Issue: Password validation failing
```json
{
  "success": false,
  "message": "Password must contain at least one uppercase letter..."
}
```

**Solution:**
```javascript
// Test password against regex
const password = "TestPassword123!";
const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
console.log(regex.test(password)); // Should be true

// Update validation if needed
const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .required();
```

#### Issue: Email validation rejecting valid emails
```bash
"Please provide a valid email address"
```

**Solution:**
```javascript
// Test email validation
const email = "test+tag@example.com";
const Joi = require('joi');
const schema = Joi.string().email();
const result = schema.validate(email);
console.log(result.error); // Should be null for valid emails
```

### 7. Logging and Debugging

#### Issue: No logs appearing
**Solutions:**
1. **Check log configuration:**
   ```javascript
   // Ensure logger is properly configured
   const Logger = require('./src/utils/logger');
   Logger.info('Test log message');
   ```

2. **Check file permissions:**
   ```bash
   # Ensure log directory is writable
   chmod 755 logs/
   touch logs/combined.log
   chmod 644 logs/combined.log
   ```

#### Issue: Too many logs (log spam)
**Solution:**
```javascript
// Adjust log level
const logLevel = process.env.LOG_LEVEL || 'info';

// Filter out noisy logs
if (config.server.nodeEnv === 'production') {
  // Only log warnings and errors
  logger.level = 'warn';
}
```

### 8. Development Environment Issues

#### Issue: Hot reload not working
**Solution:**
```bash
# Use nodemon for development
npm install -g nodemon
nodemon src/server.js

# Or use npm script
npm run dev
```

#### Issue: Environment variables not loading
**Solutions:**
1. **Check .env file location:**
   ```bash
   # .env should be in project root
   ls -la .env
   ```

2. **Verify dotenv configuration:**
   ```javascript
   // At the very top of config.js
   require('dotenv').config();
   
   // Or specify path
   require('dotenv').config({ path: '.env' });
   ```

### 9. Production Deployment Issues

#### Issue: PM2 process crashes
```bash
PM2 process stopped unexpectedly
```

**Solutions:**
1. **Check PM2 logs:**
   ```bash
   pm2 logs auth-server
   pm2 show auth-server
   ```

2. **Increase memory limit:**
   ```javascript
   // ecosystem.config.js
   module.exports = {
     apps: [{
       name: 'auth-server',
       script: 'src/server.js',
       max_memory_restart: '1G',
       instances: 'max',
       exec_mode: 'cluster'
     }]
   };
   ```

#### Issue: SSL certificate errors
```bash
SSL certificate verification failed
```

**Solutions:**
1. **Check certificate validity:**
   ```bash
   openssl x509 -in certificate.crt -text -noout
   ```

2. **Verify certificate chain:**
   ```bash
   openssl verify -CAfile ca-bundle.crt certificate.crt
   ```

### 10. Testing Issues

#### Issue: Tests failing in CI/CD
**Solutions:**
1. **Set test environment variables:**
   ```bash
   # In CI/CD pipeline
   NODE_ENV=test
   MONGODB_URI=mongodb://localhost:27017/test_db
   JWT_SECRET=test_secret
   ```

2. **Use test database:**
   ```javascript
   // Separate test configuration
   if (process.env.NODE_ENV === 'test') {
     config.database.mongoUri = 'mongodb://localhost:27017/test_db';
   }
   ```

## Debugging Tools

### 1. Health Check Script
```bash
#!/bin/bash
# health-check.sh

echo "=== Auth Server Health Check ==="

# Check if server is running
curl -f http://localhost:3001/api/health || echo "❌ Server not responding"

# Check database connection
curl -s http://localhost:3001/api/health/detailed | jq '.database.status' || echo "❌ Database check failed"

# Check memory usage
ps aux | grep node | head -1

echo "=== Health Check Complete ==="
```

### 2. Database Connection Test
```javascript
// test-db-connection.js
const mongoose = require('mongoose');
require('dotenv').config();

async function testConnection() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Database connection successful');
    
    // Test basic operations
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log('📊 Collections:', collections.map(c => c.name));
    
    await mongoose.disconnect();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
  }
}

testConnection();
```

### 3. Token Validation Test
```javascript
// test-token.js
const jwt = require('jsonwebtoken');

const token = process.argv[2];
const secret = process.env.JWT_SECRET;

try {
  const decoded = jwt.verify(token, secret);
  console.log('✅ Token valid:', decoded);
} catch (error) {
  console.error('❌ Token invalid:', error.message);
}
```

### 4. Log Analysis Commands
```bash
# Find error patterns
grep -i "error\|exception\|failed" logs/combined.log | tail -20

# Monitor real-time logs
tail -f logs/combined.log | grep -E "(ERROR|WARN)"

# Count log levels
grep -c "INFO" logs/combined.log
grep -c "ERROR" logs/combined.log
grep -c "WARN" logs/combined.log

# Find slow requests
grep "Slow request" logs/combined.log
```

## Getting Help

### 1. Enable Debug Mode
```bash
# Set debug environment
DEBUG=auth:* npm run dev

# Or specific modules
DEBUG=auth:security,auth:database npm run dev
```

### 2. Collect System Information
```bash
#!/bin/bash
# system-info.sh

echo "=== System Information ==="
echo "Node.js version: $(node --version)"
echo "NPM version: $(npm --version)"
echo "OS: $(uname -a)"
echo "Memory: $(free -h)"
echo "Disk: $(df -h)"

echo "=== Environment Variables ==="
env | grep -E "(NODE_ENV|PORT|JWT_|MONGODB_)" | sort

echo "=== Process Information ==="
ps aux | grep node
```

### 3. Create Issue Template
When reporting issues, include:
- Node.js and npm versions
- Operating system
- Environment variables (without secrets)
- Error messages and stack traces
- Steps to reproduce
- Expected vs actual behavior

This troubleshooting guide should help resolve most common issues encountered when running the Auth Server.
