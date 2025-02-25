export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxAttempts: number; // Maximum attempts per window
  skipSuccessful?: boolean; // Don't count successful attempts
}

export interface RateLimitAttempt {
  timestamp: number;
  successful: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

export class RateLimiter {
  private attempts = new Map<string, RateLimitAttempt[]>();
  private config: Required<RateLimitConfig>;

  constructor(config: RateLimitConfig) {
    this.config = {
      skipSuccessful: false,
      ...config
    };
  }

  checkLimit(identifier: string): RateLimitResult {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    
    // Get attempts for this identifier
    let userAttempts = this.attempts.get(identifier) || [];
    
    // Remove old attempts outside the window
    userAttempts = userAttempts.filter(attempt => attempt.timestamp > windowStart);
    
    // Filter out successful attempts if configured to skip them
    const countedAttempts = this.config.skipSuccessful 
      ? userAttempts.filter(attempt => !attempt.successful)
      : userAttempts;

    const currentCount = countedAttempts.length;
    const allowed = currentCount < this.config.maxAttempts;
    const remaining = Math.max(0, this.config.maxAttempts - currentCount);
    
    // Update stored attempts
    this.attempts.set(identifier, userAttempts);

    const result: RateLimitResult = {
      allowed,
      remaining,
      resetTime: now + this.config.windowMs
    };

    if (!allowed && userAttempts.length > 0) {
      const oldestAttempt = userAttempts[0];
      result.retryAfter = Math.ceil((oldestAttempt.timestamp + this.config.windowMs - now) / 1000);
    }

    return result;
  }

  recordAttempt(identifier: string, successful: boolean = false): void {
    const now = Date.now();
    const userAttempts = this.attempts.get(identifier) || [];
    
    userAttempts.push({
      timestamp: now,
      successful
    });

    this.attempts.set(identifier, userAttempts);
  }

  reset(identifier: string): void {
    this.attempts.delete(identifier);
  }

  resetAll(): void {
    this.attempts.clear();
  }

  getStats() {
    const now = Date.now();
    let totalAttempts = 0;
    let activeIdentifiers = 0;

    for (const [identifier, attempts] of this.attempts.entries()) {
      const recentAttempts = attempts.filter(
        attempt => attempt.timestamp > now - this.config.windowMs
      );
      
      if (recentAttempts.length > 0) {
        activeIdentifiers++;
        totalAttempts += recentAttempts.length;
      }
    }

    return {
      totalAttempts,
      activeIdentifiers,
      averageAttemptsPerIdentifier: activeIdentifiers > 0 
        ? totalAttempts / activeIdentifiers 
        : 0
    };
  }

  cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    for (const [identifier, attempts] of this.attempts.entries()) {
      const recentAttempts = attempts.filter(attempt => attempt.timestamp > windowStart);
      
      if (recentAttempts.length === 0) {
        this.attempts.delete(identifier);
      } else {
        this.attempts.set(identifier, recentAttempts);
      }
    }
  }
}

// Pre-configured rate limiters for common use cases
export class AuthRateLimiters {
  static readonly emailMagicLink = new RateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 3, // 3 magic link requests per 15 minutes
    skipSuccessful: true
  });

  static readonly tokenVerification = new RateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxAttempts: 10, // 10 token verifications per 5 minutes
    skipSuccessful: true
  });

  static readonly webauthnAttempts = new RateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    maxAttempts: 5, // 5 WebAuthn attempts per 10 minutes
    skipSuccessful: true
  });

  static readonly generalAuth = new RateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 20, // 20 auth attempts per 15 minutes
    skipSuccessful: false
  });
}