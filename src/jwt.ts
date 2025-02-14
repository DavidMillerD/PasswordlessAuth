import * as jwt from 'jsonwebtoken';
import { VerifyTokenResult, UserInfo } from './types';

export class JWTManager {
  constructor(
    private secret: string,
    private defaultExpiry: string = '1h'
  ) {}

  generateToken(user: UserInfo, expiresIn?: string): string {
    const payload = {
      userId: user.id,
      email: user.email,
      iat: Math.floor(Date.now() / 1000)
    };

    return jwt.sign(payload, this.secret, {
      expiresIn: expiresIn || this.defaultExpiry,
      algorithm: 'HS256'
    });
  }

  verifyToken(token: string): VerifyTokenResult {
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: ['HS256']
      });

      return {
        valid: true,
        payload: decoded
      };
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          valid: false,
          error: 'Invalid token'
        };
      }
      
      if (error instanceof jwt.TokenExpiredError) {
        return {
          valid: false,
          error: 'Token expired'
        };
      }

      return {
        valid: false,
        error: 'Token verification failed'
      };
    }
  }

  refreshToken(token: string): string | null {
    const result = this.verifyToken(token);
    
    if (!result.valid || !result.payload) {
      return null;
    }

    const user: UserInfo = {
      id: result.payload.userId,
      email: result.payload.email,
      createdAt: new Date(),
      lastLogin: new Date()
    };

    return this.generateToken(user);
  }

  decodeToken(token: string): any {
    return jwt.decode(token);
  }
}