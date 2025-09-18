# Deployment Guide

## Overview

This guide covers deploying the Auth Server to various environments including local development, staging, and production deployments.

## Prerequisites

- Node.js 16+ installed
- MongoDB Atlas account or MongoDB server
- SSL certificate for production
- Domain name configured (production)

## Local Development Deployment

### 1. Environment Setup
```bash
# Clone and setup
git clone <repository-url>
cd auth-server

# Install dependencies
npm install

# Create environment file
cp .env.example .env
```

### 2. Configure Environment
```bash
# .env for development
NODE_ENV=development
PORT=3001

JWT_SECRET=dev_jwt_secret_key
JWT_REFRESH_SECRET=dev_refresh_secret_key

MONGODB_URI=mongodb://localhost:27017/scalai_auth_dev
DB_NAME=scalai_auth_dev

BCRYPT_SALT_ROUNDS=4
CORS_ORIGIN=http://localhost:3000
```

### 3. Start Development Server
```bash
# Start with auto-reload
npm run dev

# Start with database clearing
npm run dev:clear

# Start in production mode
npm start
```

## Docker Deployment

### 1. Dockerfile
```dockerfile
# Use official Node.js runtime
FROM node:18.17.0-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S authuser -u 1001

# Change ownership
RUN chown -R authuser:nodejs /app
USER authuser

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

# Start application
CMD ["npm", "start"]
```

### 2. Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  auth-server:
    build: .
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
      - MONGODB_URI=${MONGODB_URI}
      - JWT_SECRET=${JWT_SECRET}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
    depends_on:
      - mongodb
    restart: unless-stopped
    networks:
      - auth-network

  mongodb:
    image: mongo:6.0
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password
      - MONGO_INITDB_DATABASE=scalai_auth
    volumes:
      - mongodb_data:/data/db
    networks:
      - auth-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - auth-server
    networks:
      - auth-network

volumes:
  mongodb_data:

networks:
  auth-network:
    driver: bridge
```

### 3. Build and Run
```bash
# Build image
docker build -t auth-server .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f auth-server

# Stop services
docker-compose down
```

## Cloud Deployment

### AWS Deployment (EC2)

#### 1. EC2 Instance Setup
```bash
# Launch Ubuntu 20.04 LTS instance
# Security Group: Allow ports 22, 80, 443, 3001

# Connect to instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Install Nginx
sudo apt install nginx -y
```

#### 2. Application Deployment
```bash
# Clone repository
git clone <repository-url>
cd auth-server

# Install dependencies
npm install --production

# Create production environment file
sudo nano .env
```

#### 3. PM2 Configuration
```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'auth-server',
    script: 'src/server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: 3001
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3001
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
};
```

#### 4. Start with PM2
```bash
# Create logs directory
mkdir logs

# Start application
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save

# Setup PM2 startup
pm2 startup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u ubuntu --hp /home/ubuntu
```

#### 5. Nginx Configuration
```nginx
# /etc/nginx/sites-available/auth-server
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
    limit_req zone=auth burst=20 nodelay;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

#### 6. Enable Nginx Site
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/auth-server /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx

# Enable auto-start
sudo systemctl enable nginx
```

### Heroku Deployment

#### 1. Prepare Application
```bash
# Create Procfile
echo "web: npm start" > Procfile

# Update package.json
{
  "scripts": {
    "start": "node src/server.js",
    "heroku-postbuild": "echo 'Build complete'"
  },
  "engines": {
    "node": "18.x",
    "npm": "9.x"
  }
}
```

#### 2. Deploy to Heroku
```bash
# Install Heroku CLI
npm install -g heroku

# Login to Heroku
heroku login

# Create app
heroku create your-auth-server

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set JWT_SECRET=your-production-jwt-secret
heroku config:set JWT_REFRESH_SECRET=your-production-refresh-secret
heroku config:set MONGODB_URI=your-mongodb-atlas-uri

# Deploy
git push heroku main

# View logs
heroku logs --tail
```

### DigitalOcean App Platform

#### 1. App Spec File
```yaml
# .do/app.yaml
name: auth-server
services:
- name: api
  source_dir: /
  github:
    repo: your-username/auth-server
    branch: main
  run_command: npm start
  environment_slug: node-js
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: NODE_ENV
    value: production
  - key: JWT_SECRET
    value: ${JWT_SECRET}
  - key: JWT_REFRESH_SECRET
    value: ${JWT_REFRESH_SECRET}
  - key: MONGODB_URI
    value: ${MONGODB_URI}
  http_port: 3001
  health_check:
    http_path: /api/health
```

#### 2. Deploy
```bash
# Install doctl
# Configure DigitalOcean CLI

# Create app
doctl apps create .do/app.yaml

# Update app
doctl apps update <app-id> .do/app.yaml
```

## Production Configuration

### Environment Variables
```bash
# Production .env
NODE_ENV=production
PORT=3001

# Strong secrets (256-bit)
JWT_SECRET=your_256_bit_production_secret
JWT_REFRESH_SECRET=your_256_bit_production_refresh_secret

# Production MongoDB
MONGODB_URI=mongodb+srv://prod_user:strong_password@cluster.mongodb.net/scalai_auth_prod
DB_NAME=scalai_auth_prod

# Security settings
BCRYPT_SALT_ROUNDS=12
CORS_ORIGIN=https://your-domain.com

# Monitoring
ENABLE_SECURITY_ALERTS=true
LOG_LEVEL=info
```

### SSL/TLS Configuration

#### Let's Encrypt (Free SSL)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Custom SSL Certificate
```bash
# Copy certificates
sudo cp your-certificate.crt /etc/ssl/certs/
sudo cp your-private-key.key /etc/ssl/private/

# Set permissions
sudo chmod 600 /etc/ssl/private/your-private-key.key
sudo chmod 644 /etc/ssl/certs/your-certificate.crt
```

## Monitoring & Logging

### Application Monitoring
```bash
# Install monitoring tools
npm install --save express-prometheus-middleware
npm install --save winston
```

### Log Management
```javascript
// winston configuration
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}
```

### Health Monitoring
```bash
# Setup monitoring endpoints
curl -f http://localhost:3001/api/health || exit 1

# Monitor with external services
# - UptimeRobot
# - Pingdom
# - New Relic
# - DataDog
```

## Backup & Recovery

### Database Backup
```bash
# MongoDB backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/mongodb"
DB_NAME="scalai_auth_prod"

mkdir -p $BACKUP_DIR

# Create backup
mongodump --uri="$MONGODB_URI" --db=$DB_NAME --out=$BACKUP_DIR/$DATE

# Compress backup
tar -czf $BACKUP_DIR/backup_$DATE.tar.gz $BACKUP_DIR/$DATE

# Remove uncompressed backup
rm -rf $BACKUP_DIR/$DATE

# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.tar.gz" -mtime +7 -delete
```

### Application Backup
```bash
# Backup application files
rsync -av --exclude node_modules --exclude logs /path/to/auth-server/ /backups/app/
```

## Security Hardening

### Server Security
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable

# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Install fail2ban
sudo apt install fail2ban -y
```

### Application Security
```bash
# Run security audit
npm audit

# Fix vulnerabilities
npm audit fix

# Check for outdated packages
npm outdated
```

## Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Find process using port
sudo lsof -i :3001

# Kill process
sudo kill -9 <PID>
```

#### 2. MongoDB Connection Issues
```bash
# Test MongoDB connection
mongo "mongodb+srv://cluster.mongodb.net/test" --username user

# Check network connectivity
ping cluster.mongodb.net
```

#### 3. SSL Certificate Issues
```bash
# Test SSL certificate
openssl s_client -connect your-domain.com:443

# Check certificate expiration
echo | openssl s_client -servername your-domain.com -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates
```

#### 4. Memory Issues
```bash
# Monitor memory usage
htop

# Check Node.js memory usage
node --max-old-space-size=4096 src/server.js
```

### Log Analysis
```bash
# View application logs
tail -f logs/combined.log

# Search for errors
grep -i error logs/combined.log

# Monitor real-time logs with PM2
pm2 logs auth-server
```

## Performance Optimization

### Node.js Optimization
```javascript
// Cluster mode for CPU utilization
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
} else {
  require('./server');
}
```

### Database Optimization
```javascript
// MongoDB connection optimization
mongoose.connect(uri, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  bufferMaxEntries: 0,
  useNewUrlParser: true,
  useUnifiedTopology: true
});
```

### Caching
```javascript
// Redis caching (optional)
const redis = require('redis');
const client = redis.createClient();

// Cache frequently accessed data
app.get('/api/user/:id', cache('5 minutes'), getUserHandler);
```

This deployment guide provides comprehensive instructions for deploying the Auth Server across different environments with proper security, monitoring, and optimization configurations.
