const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../../config/config');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    const decoded = jwt.verify(token, config.jwt.secret);
    
    // Find user and check if still active
    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'User not found or inactive'
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired'
      });
    }
    
    return res.status(403).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

const generateTokens = async (user, userAgent, ipAddress) => {
  const payload = {
    id: user._id.toString(),
    email: user.email,
    role: user.role // Add role to JWT payload
  };

  // Generate access token
  const accessToken = jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn
  });

  // Generate refresh token
  const refreshTokenString = crypto.randomBytes(40).toString('hex');
  const refreshToken = jwt.sign(
    { ...payload, tokenId: refreshTokenString }, 
    config.jwt.refreshSecret, 
    { expiresIn: config.jwt.refreshExpiresIn }
  );

  // Store refresh token in database
  const expiresIn = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
  await RefreshToken.createToken(
    user._id,
    refreshTokenString,
    expiresIn,
    userAgent,
    ipAddress
  );

  return { accessToken, refreshToken };
};

const verifyRefreshToken = async (token) => {
  try {
    const decoded = jwt.verify(token, config.jwt.refreshSecret);
    
    // Check if token exists in database and is valid
    const storedToken = await RefreshToken.findValidToken(decoded.tokenId);
    
    if (!storedToken) {
      throw new Error('Invalid refresh token');
    }

    // Check if user is still active
    if (!storedToken.user.isActive) {
      throw new Error('User account is inactive');
    }

    return {
      success: true,
      user: storedToken.user,
      tokenId: decoded.tokenId
    };
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

const revokeRefreshToken = async (tokenId) => {
  try {
    await RefreshToken.revokeToken(tokenId);
    return { success: true };
  } catch (error) {
    throw new Error('Failed to revoke token');
  }
};

const revokeAllUserTokens = async (userId) => {
  try {
    await RefreshToken.revokeAllUserTokens(userId);
    return { success: true };
  } catch (error) {
    throw new Error('Failed to revoke user tokens');
  }
};

module.exports = {
  authenticateToken,
  generateTokens,
  verifyRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens
};
