import * as jwt from 'jsonwebtoken';
import { createHash } from './utils';

export interface BlacklistedToken {
  jti: string; // JWT ID (hash of the token)
  exp: number; // Expiration timestamp
  userId?: string;
  reason?: string;
  blacklistedAt: number;
}

export interface BlacklistConfig {
  cleanupInterval?: number; // milliseconds
  maxSize?: number; // maximum number of tokens to keep
}

export class TokenBlacklist {
  private blacklistedTokens = new Map<string, BlacklistedToken>();
  private cleanupTimer?: NodeJS.Timeout;

  constructor(private config: BlacklistConfig = {}) {
    const defaultConfig = {
      cleanupInterval: 60 * 60 * 1000, // 1 hour
      maxSize: 10000 // 10k tokens max
    };
    
    this.config = { ...defaultConfig, ...config };
    this.startCleanup();
  }

  blacklistToken(
    token: string, 
    reason?: string, 
    userId?: string
  ): boolean {
    try {
      // Decode token without verification to get expiration
      const decoded = jwt.decode(token) as any;
      
      if (!decoded || !decoded.exp) {
        return false;
      }

      const jti = createHash(token);
      const blacklistedToken: BlacklistedToken = {
        jti,
        exp: decoded.exp * 1000, // Convert to milliseconds
        userId: userId || decoded.userId,
        reason,
        blacklistedAt: Date.now()
      };

      this.blacklistedTokens.set(jti, blacklistedToken);
      
      // Cleanup if we exceed max size
      if (this.config.maxSize && this.blacklistedTokens.size > this.config.maxSize) {
        this.cleanup();
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  isTokenBlacklisted(token: string): boolean {
    const jti = createHash(token);
    const blacklistedToken = this.blacklistedTokens.get(jti);
    
    if (!blacklistedToken) {
      return false;
    }

    // Check if token has expired naturally
    if (blacklistedToken.exp < Date.now()) {
      this.blacklistedTokens.delete(jti);
      return false;
    }

    return true;
  }

  blacklistAllUserTokens(userId: string, reason?: string): number {
    let count = 0;
    const tokensToBlacklist: string[] = [];

    // Find all tokens for this user
    for (const [jti, tokenData] of this.blacklistedTokens.entries()) {
      if (tokenData.userId === userId) {
        tokensToBlacklist.push(jti);
      }
    }

    // This is a simplified approach - in a real implementation,
    // you might need to track active tokens or use a different strategy
    return count;
  }

  removeToken(token: string): boolean {
    const jti = createHash(token);
    return this.blacklistedTokens.delete(jti);
  }

  getBlacklistedTokenInfo(token: string): BlacklistedToken | null {
    const jti = createHash(token);
    return this.blacklistedTokens.get(jti) || null;
  }

  getStats() {
    const now = Date.now();
    let expiredCount = 0;
    let activeCount = 0;

    for (const [, tokenData] of this.blacklistedTokens.entries()) {
      if (tokenData.exp < now) {
        expiredCount++;
      } else {
        activeCount++;
      }
    }

    return {
      total: this.blacklistedTokens.size,
      active: activeCount,
      expired: expiredCount,
      maxSize: this.config.maxSize
    };
  }

  cleanup(): void {
    const now = Date.now();
    const expiredTokens: string[] = [];

    // Find expired tokens
    for (const [jti, tokenData] of this.blacklistedTokens.entries()) {
      if (tokenData.exp < now) {
        expiredTokens.push(jti);
      }
    }

    // Remove expired tokens
    for (const jti of expiredTokens) {
      this.blacklistedTokens.delete(jti);
    }

    // If still over limit, remove oldest tokens
    if (this.config.maxSize && this.blacklistedTokens.size > this.config.maxSize) {
      const sortedTokens = Array.from(this.blacklistedTokens.entries())
        .sort((a, b) => a[1].blacklistedAt - b[1].blacklistedAt);

      const tokensToRemove = sortedTokens.slice(0, this.blacklistedTokens.size - this.config.maxSize);
      for (const [jti] of tokensToRemove) {
        this.blacklistedTokens.delete(jti);
      }
    }
  }

  private startCleanup(): void {
    if (this.config.cleanupInterval && this.config.cleanupInterval > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanup();
      }, this.config.cleanupInterval);
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    this.blacklistedTokens.clear();
  }

  // Utility methods for common blacklisting scenarios
  blacklistExpiredToken(token: string): boolean {
    return this.blacklistToken(token, 'Token expired');
  }

  blacklistCompromisedToken(token: string, userId?: string): boolean {
    return this.blacklistToken(token, 'Security compromise', userId);
  }

  blacklistLogoutToken(token: string, userId?: string): boolean {
    return this.blacklistToken(token, 'User logout', userId);
  }
}