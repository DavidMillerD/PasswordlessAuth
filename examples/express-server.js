const express = require('express');
const cookieParser = require('cookie-parser');
const { PasswordlessAuth, createDefaultAuthMiddleware } = require('../dist');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Initialize auth with configuration
const auth = new PasswordlessAuth({
  jwtSecret: process.env.JWT_SECRET || 'demo-secret-change-in-production',
  emailConfig: {
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: parseInt(process.env.SMTP_PORT) || 587,
    user: process.env.SMTP_USER || 'test@ethereal.email',
    pass: process.env.SMTP_PASS || 'password123',
    fromEmail: process.env.FROM_EMAIL || 'noreply@example.com',
    fromName: process.env.FROM_NAME || 'Demo App'
  },
  webauthnConfig: {
    rpName: 'Demo App',
    rpId: process.env.WEBAUTHN_RP_ID || 'localhost',
    origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'
  }
});

// Create middleware
const authMiddleware = createDefaultAuthMiddleware(auth);

// Public routes
app.post('/auth/magic-link', 
  authMiddleware.rateLimit('email'),
  async (req, res, next) => {
    try {
      const { email, redirectUrl } = req.body;
      
      const result = await auth.sendMagicLink({
        email,
        redirectUrl: redirectUrl || 'http://localhost:3000/auth/callback'
      });

      if (result.success) {
        authMiddleware.recordSuccess(req.ip);
        res.json({ message: 'Magic link sent successfully' });
      } else {
        res.status(400).json({ error: result.error });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.post('/auth/verify-magic-link',
  authMiddleware.rateLimit('token'),
  async (req, res, next) => {
    try {
      const { token } = req.body;
      
      const result = await auth.verifyMagicLink(token);
      
      if (result.success) {
        authMiddleware.recordSuccess(req.ip);
        
        // Set cookie
        res.cookie('auth_token', result.token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({
          message: 'Authentication successful',
          user: result.user,
          token: result.token
        });
      } else {
        res.status(401).json({ error: result.error });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.get('/auth/webauthn/register/:email',
  authMiddleware.rateLimit('webauthn'),
  (req, res) => {
    try {
      const { email } = req.params;
      const userId = `user_${Date.now()}`;
      
      const options = auth.generateWebAuthnRegistrationOptions(userId, email);
      
      res.json(options);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }
);

app.get('/auth/webauthn/login',
  authMiddleware.rateLimit('webauthn'),
  (req, res) => {
    try {
      const options = auth.generateWebAuthnAuthenticationOptions();
      res.json(options);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }
);

// Protected routes
app.get('/profile',
  authMiddleware.authenticateToken(),
  (req, res) => {
    res.json({
      message: 'Welcome to your profile',
      user: req.user
    });
  }
);

app.post('/logout',
  authMiddleware.authenticateToken(),
  (req, res) => {
    try {
      const token = authMiddleware.extractToken(req);
      
      if (token && authMiddleware.config.blacklist) {
        authMiddleware.config.blacklist.blacklistLogoutToken(token, req.user?.userId);
      }
      
      res.clearCookie('auth_token');
      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Logout failed' });
    }
  }
);

// Optional protected route
app.get('/optional-auth',
  authMiddleware.authenticateToken(false), // Not required
  (req, res) => {
    res.json({
      message: 'This route works with or without authentication',
      authenticated: !!req.user,
      user: req.user || null
    });
  }
);

// Admin routes (example of additional protection)
app.get('/admin/stats',
  authMiddleware.authenticateToken(),
  (req, res) => {
    // Check if user is admin (simplified check)
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    res.json({
      rateLimitStats: authMiddleware.config.rateLimiters?.generalAuth.getStats(),
      blacklistStats: authMiddleware.config.blacklist?.getStats(),
      logStats: authMiddleware.config.logger?.getStats()
    });
  }
);

// Error handling
app.use(authMiddleware.errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Available endpoints:');
  console.log('  POST /auth/magic-link');
  console.log('  POST /auth/verify-magic-link');
  console.log('  GET  /auth/webauthn/register/:email');
  console.log('  GET  /auth/webauthn/login');
  console.log('  GET  /profile (protected)');
  console.log('  POST /logout (protected)');
  console.log('  GET  /optional-auth');
  console.log('  GET  /admin/stats (protected, admin only)');
});