import { MagicLinkAuth } from './magic-link';
import { WebAuthnAuth } from './webauthn';
import { JWTManager } from './jwt';
import { 
  AuthConfig, 
  AuthResult, 
  MagicLinkOptions, 
  UserInfo,
  VerifyTokenResult,
  EmailConfig,
  WebAuthnConfig 
} from './types';
import { generateSecureToken, isValidEmail } from './utils';

export class PasswordlessAuth {
  private magicLinkAuth?: MagicLinkAuth;
  private webAuthnAuth?: WebAuthnAuth;
  private jwtManager: JWTManager;
  private users = new Map<string, UserInfo>();

  constructor(private config: AuthConfig) {
    this.jwtManager = new JWTManager(config.jwtSecret, config.jwtExpiry);
    
    if (config.emailConfig) {
      this.magicLinkAuth = new MagicLinkAuth(config.emailConfig);
    }
    
    if (config.webauthnConfig) {
      this.webAuthnAuth = new WebAuthnAuth(config.webauthnConfig);
    }
  }

  async sendMagicLink(options: MagicLinkOptions): Promise<AuthResult> {
    if (!this.magicLinkAuth) {
      return { success: false, error: 'Magic link not configured' };
    }

    const result = await this.magicLinkAuth.sendMagicLink(options);
    
    if (!result.success) {
      return { success: false, error: result.error };
    }

    return { success: true };
  }

  async verifyMagicLink(token: string): Promise<AuthResult> {
    if (!this.magicLinkAuth) {
      return { success: false, error: 'Magic link not configured' };
    }

    const verification = this.magicLinkAuth.verifyMagicToken(token);
    
    if (!verification.valid) {
      return { success: false, error: verification.error };
    }

    const user = await this.getOrCreateUser(verification.email!);
    const authToken = this.jwtManager.generateToken(user);

    return {
      success: true,
      token: authToken,
      user
    };
  }

  generateWebAuthnRegistrationOptions(userId: string, email: string) {
    if (!this.webAuthnAuth) {
      throw new Error('WebAuthn not configured');
    }

    return this.webAuthnAuth.generateRegistrationOptions(userId, email, email);
  }

  generateWebAuthnAuthenticationOptions() {
    if (!this.webAuthnAuth) {
      throw new Error('WebAuthn not configured');
    }

    return this.webAuthnAuth.generateAuthenticationOptions();
  }

  async verifyWebAuthnRegistration(credential: PublicKeyCredential, email: string): Promise<AuthResult> {
    if (!this.webAuthnAuth) {
      return { success: false, error: 'WebAuthn not configured' };
    }

    const result = await this.webAuthnAuth.verifyRegistration(credential);
    
    if (!result.verified) {
      return { success: false, error: result.error };
    }

    const user = await this.getOrCreateUser(email);
    const token = this.jwtManager.generateToken(user);

    return {
      success: true,
      token,
      user
    };
  }

  async verifyWebAuthnAuthentication(credential: PublicKeyCredential): Promise<AuthResult> {
    if (!this.webAuthnAuth) {
      return { success: false, error: 'WebAuthn not configured' };
    }

    const result = await this.webAuthnAuth.verifyAuthentication(credential);
    
    if (!result.verified) {
      return { success: false, error: result.error };
    }

    return { success: true };
  }

  verifyToken(token: string): VerifyTokenResult {
    return this.jwtManager.verifyToken(token);
  }

  refreshToken(token: string): string | null {
    return this.jwtManager.refreshToken(token);
  }

  private async getOrCreateUser(email: string): Promise<UserInfo> {
    let user = Array.from(this.users.values()).find(u => u.email === email);
    
    if (!user) {
      user = {
        id: generateSecureToken(16),
        email,
        createdAt: new Date(),
        lastLogin: new Date()
      };
      this.users.set(user.id, user);
    } else {
      user.lastLogin = new Date();
    }

    return user;
  }
}

export * from './types';
export { generateSecureToken, isValidEmail } from './utils';
export { AuthError, AuthErrorCode, createAuthError } from './errors';
export { SessionManager, SessionData, SessionConfig } from './session';
export { RateLimiter, AuthRateLimiters, RateLimitConfig } from './rate-limiter';
export { TokenBlacklist, BlacklistedToken, BlacklistConfig } from './blacklist';
export { AuthLogger, LogLevel, LogEntry, defaultLogger } from './logger';
export { 
  ExpressAuthMiddleware, 
  createAuthMiddleware, 
  createDefaultAuthMiddleware,
  MiddlewareConfig 
} from './express-middleware';