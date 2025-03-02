# PasswordlessAuth

A comprehensive TypeScript library for passwordless authentication supporting magic links and WebAuthn biometric authentication with enterprise-grade security features.

## Features

### Core Authentication
- 🔗 **Magic link authentication** via email with customizable templates
- 🔐 **WebAuthn biometric authentication** (fingerprint, face ID, security keys)
- 🎫 **JWT token management** with automatic refresh capabilities
- 📧 **Email integration** with nodemailer support for various providers

### Security & Protection
- 🛡️ **Rate limiting** with configurable limits per endpoint type
- 🚫 **Token blacklist** for secure logout and compromised token handling  
- 👥 **Session management** with multi-device support and cleanup
- 🔍 **Comprehensive logging** with security event tracking
- ⚠️ **Custom error handling** with detailed error codes and sanitization

### Integration
- 🚀 **Express.js middleware** with plug-and-play authentication
- 🔒 **Flexible token extraction** from headers, cookies, or both
- 📊 **Admin dashboard support** with statistics and monitoring
- 🛠️ **TypeScript support** with full type definitions

## Installation

```bash
npm install passwordless-auth
```

## Quick Start

### Magic Link Authentication

```typescript
import { PasswordlessAuth } from 'passwordless-auth';

const auth = new PasswordlessAuth({
  jwtSecret: 'your-secret-key',
  emailConfig: {
    host: 'smtp.gmail.com',
    port: 587,
    user: 'your-email@gmail.com',
    pass: 'your-password',
    fromEmail: 'noreply@yourapp.com'
  }
});

// Send magic link
await auth.sendMagicLink({
  email: 'user@example.com',
  redirectUrl: 'https://yourapp.com/auth'
});

// Verify magic link token
const result = await auth.verifyMagicLink(token);
if (result.success) {
  console.log('User authenticated:', result.user);
  console.log('JWT token:', result.token);
}
```

### WebAuthn Biometric Authentication

```typescript
const auth = new PasswordlessAuth({
  jwtSecret: 'your-secret-key',
  webauthnConfig: {
    rpName: 'Your App',
    rpId: 'yourapp.com',
    origin: 'https://yourapp.com'
  }
});

// Registration
const registrationOptions = auth.generateWebAuthnRegistrationOptions(
  'user-id',
  'user@example.com'
);

// After user completes registration in browser
const registrationResult = await auth.verifyWebAuthnRegistration(
  credential,
  'user@example.com'
);

// Authentication
const authOptions = auth.generateWebAuthnAuthenticationOptions();

// After user completes authentication in browser  
const authResult = await auth.verifyWebAuthnAuthentication(credential);
```

### Express.js Integration

```typescript
import express from 'express';
import { PasswordlessAuth, createDefaultAuthMiddleware } from 'passwordless-auth';

const app = express();
const auth = new PasswordlessAuth({ /* config */ });
const authMiddleware = createDefaultAuthMiddleware(auth);

// Apply rate limiting
app.post('/auth/magic-link', 
  authMiddleware.rateLimit('email'),
  async (req, res) => {
    // Handle magic link request
  }
);

// Protect routes
app.get('/profile',
  authMiddleware.authenticateToken(),
  (req, res) => {
    res.json({ user: req.user });
  }
);

// Optional authentication
app.get('/public-or-private',
  authMiddleware.authenticateToken(false),
  (req, res) => {
    res.json({ 
      authenticated: !!req.user,
      user: req.user || null 
    });
  }
);

// Error handling
app.use(authMiddleware.errorHandler);
```

### Advanced Features

#### Session Management
```typescript
import { SessionManager } from 'passwordless-auth';

const sessionManager = new SessionManager({
  sessionDuration: 24 * 60 * 60 * 1000, // 24 hours
  maxSessionsPerUser: 5
});

const session = sessionManager.createSession(userInfo, {
  ipAddress: req.ip,
  userAgent: req.get('user-agent')
});
```

#### Token Blacklist
```typescript
import { TokenBlacklist } from 'passwordless-auth';

const blacklist = new TokenBlacklist();

// Blacklist token on logout
blacklist.blacklistLogoutToken(token, userId);

// Check if token is blacklisted
const isBlacklisted = blacklist.isTokenBlacklisted(token);
```

#### Rate Limiting
```typescript
import { RateLimiter } from 'passwordless-auth';

const limiter = new RateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 3
});

const result = limiter.checkLimit(clientId);
if (!result.allowed) {
  throw new Error(`Rate limit exceeded. Retry after ${result.retryAfter} seconds`);
}
```

#### Comprehensive Logging
```typescript
import { AuthLogger, LogLevel } from 'passwordless-auth';

const logger = new AuthLogger({ level: LogLevel.INFO });

// Auth-specific logging methods
logger.logAuthAttempt(email, 'magic-link', true);
logger.logSecurityEvent('suspicious-activity', 'high');
logger.logTokenVerification(false, 'Token expired');

// Query logs
const recentErrors = logger.getLogs({
  level: LogLevel.ERROR,
  startDate: new Date(Date.now() - 24 * 60 * 60 * 1000)
});
```

## Security Best Practices

1. **Environment Variables**: Always use environment variables for secrets
2. **HTTPS**: Use HTTPS in production for all authentication endpoints
3. **Rate Limiting**: Enable rate limiting to prevent brute force attacks
4. **Token Blacklist**: Implement token blacklisting for secure logout
5. **Session Management**: Use session management for multi-device tracking
6. **Logging**: Enable comprehensive logging for security monitoring

## Error Handling

The library provides structured error handling with specific error codes:

- `INVALID_EMAIL`: Invalid email address format
- `TOKEN_EXPIRED`: JWT token has expired
- `RATE_LIMIT_EXCEEDED`: Too many authentication attempts
- `VERIFICATION_FAILED`: Authentication verification failed

## TypeScript Support

Full TypeScript support with comprehensive type definitions for all interfaces and functions.

## Examples

See the `/examples` directory for:
- Basic usage examples
- Complete Express.js server implementation
- Advanced security configurations

## License

MIT