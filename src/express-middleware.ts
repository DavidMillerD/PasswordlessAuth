import { Request, Response, NextFunction } from 'express';
import { PasswordlessAuth } from './index';
import { AuthError, AuthErrorCode, createAuthError } from './errors';
import { AuthRateLimiters } from './rate-limiter';
import { TokenBlacklist } from './blacklist';
import { AuthLogger, defaultLogger } from './logger';

// Extend Request interface to include auth data
declare module 'express-serve-static-core' {
  interface Request {
    user?: any;
    session?: any;
    authContext?: {
      userId?: string;
      sessionId?: string;
      ipAddress?: string;
      userAgent?: string;
    };
  }
}

export interface MiddlewareConfig {
  auth: PasswordlessAuth;
  blacklist?: TokenBlacklist;
  logger?: AuthLogger;
  skipRateLimit?: boolean;
  extractTokenFrom?: 'header' | 'cookie' | 'both';
  tokenHeaderName?: string;
  tokenCookieName?: string;
}

export class ExpressAuthMiddleware {
  private config: Required<MiddlewareConfig>;

  constructor(config: MiddlewareConfig) {
    this.config = {
      blacklist: new TokenBlacklist(),
      logger: defaultLogger,
      skipRateLimit: false,
      extractTokenFrom: 'header',
      tokenHeaderName: 'authorization',
      tokenCookieName: 'auth_token',
      ...config
    };
  }

  // Rate limiting middleware
  rateLimit(limiterType: 'general' | 'email' | 'webauthn' | 'token' = 'general') = (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    if (this.config.skipRateLimit) {
      return next();
    }

    const identifier = this.getClientIdentifier(req);
    let limiter;

    switch (limiterType) {
      case 'email':
        limiter = AuthRateLimiters.emailMagicLink;
        break;
      case 'webauthn':
        limiter = AuthRateLimiters.webauthnAttempts;
        break;
      case 'token':
        limiter = AuthRateLimiters.tokenVerification;
        break;
      default:
        limiter = AuthRateLimiters.generalAuth;
    }

    const result = limiter.checkLimit(identifier);
    
    if (!result.allowed) {
      this.config.logger.logRateLimit(identifier, limiterType, true, {
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });

      const error = createAuthError(AuthErrorCode.RATE_LIMIT_EXCEEDED);
      return res.status(error.statusCode).json({
        ...error.toJSON(),
        retryAfter: result.retryAfter
      });
    }

    // Record the attempt (will be marked as successful/failed later)
    req.authContext = {
      ...req.authContext,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    };

    this.config.logger.logRateLimit(identifier, limiterType, false, req.authContext);
    next();
  };

  // Token authentication middleware
  authenticateToken = (required: boolean = true) => (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    try {
      const token = this.extractToken(req);

      if (!token) {
        if (required) {
          const error = createAuthError(AuthErrorCode.TOKEN_INVALID);
          this.config.logger.logTokenVerification(false, 'No token provided', req.authContext);
          return res.status(error.statusCode).json(error.toJSON());
        }
        return next();
      }

      // Check if token is blacklisted
      if (this.config.blacklist?.isTokenBlacklisted(token)) {
        const error = createAuthError(AuthErrorCode.TOKEN_INVALID, 'Token has been revoked');
        this.config.logger.logTokenVerification(false, 'Token blacklisted', req.authContext);
        return res.status(error.statusCode).json(error.toJSON());
      }

      // Verify token
      const verification = this.config.auth.verifyToken(token);

      if (!verification.valid) {
        const error = createAuthError(
          verification.error === 'Token expired' ? AuthErrorCode.TOKEN_EXPIRED : AuthErrorCode.TOKEN_INVALID,
          verification.error
        );
        this.config.logger.logTokenVerification(false, verification.error, req.authContext);
        return res.status(error.statusCode).json(error.toJSON());
      }

      // Add user info to request
      req.user = verification.payload;
      req.authContext = {
        ...req.authContext,
        userId: verification.payload?.userId
      };

      this.config.logger.logTokenVerification(true, 'Token verified', req.authContext);
      next();
    } catch (error) {
      const authError = createAuthError(AuthErrorCode.VERIFICATION_FAILED);
      this.config.logger.error('Token verification error', error, req.authContext);
      res.status(authError.statusCode).json(authError.toJSON());
    }
  };

  // Magic link request middleware
  sendMagicLink = (req: Request, res: Response, next: NextFunction) => {
    const identifier = this.getClientIdentifier(req);
    
    // Record attempt for rate limiting
    AuthRateLimiters.emailMagicLink.recordAttempt(identifier, false);

    next();
  };

  // Error handling middleware
  errorHandler = (
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    if (error instanceof AuthError) {
      this.config.logger.error('Auth error', error.toJSON(), req.authContext);
      return res.status(error.statusCode).json(error.toJSON());
    }

    // Log unexpected errors
    this.config.logger.error('Unexpected error', {
      message: error.message,
      stack: error.stack
    }, req.authContext);

    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        statusCode: 500
      }
    });
  };

  // Utility methods
  private extractToken(req: Request): string | null {
    let token: string | null = null;

    if (this.config.extractTokenFrom === 'header' || this.config.extractTokenFrom === 'both') {
      const authHeader = req.get(this.config.tokenHeaderName);
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (!token && (this.config.extractTokenFrom === 'cookie' || this.config.extractTokenFrom === 'both')) {
      token = req.cookies?.[this.config.tokenCookieName] || null;
    }

    return token;
  }

  private getClientIdentifier(req: Request): string {
    return req.ip || 'unknown';
  }

  // Helper method to record successful auth attempts
  recordSuccess = (identifier?: string) => {
    if (identifier) {
      AuthRateLimiters.generalAuth.recordAttempt(identifier, true);
      AuthRateLimiters.emailMagicLink.recordAttempt(identifier, true);
      AuthRateLimiters.webauthnAttempts.recordAttempt(identifier, true);
      AuthRateLimiters.tokenVerification.recordAttempt(identifier, true);
    }
  };
}

// Factory function for easy setup
export function createAuthMiddleware(config: MiddlewareConfig): ExpressAuthMiddleware {
  return new ExpressAuthMiddleware(config);
}

// Pre-configured middleware for common use cases
export function createDefaultAuthMiddleware(auth: PasswordlessAuth): ExpressAuthMiddleware {
  return new ExpressAuthMiddleware({
    auth,
    blacklist: new TokenBlacklist(),
    logger: defaultLogger
  });
}