export enum AuthErrorCode {
  INVALID_EMAIL = 'INVALID_EMAIL',
  EMAIL_CONFIG_MISSING = 'EMAIL_CONFIG_MISSING',
  WEBAUTHN_CONFIG_MISSING = 'WEBAUTHN_CONFIG_MISSING',
  TOKEN_INVALID = 'TOKEN_INVALID',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  VERIFICATION_FAILED = 'VERIFICATION_FAILED',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS'
}

export class AuthError extends Error {
  constructor(
    public code: AuthErrorCode,
    message: string,
    public statusCode: number = 400
  ) {
    super(message);
    this.name = 'AuthError';
    Object.setPrototypeOf(this, AuthError.prototype);
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        statusCode: this.statusCode
      }
    };
  }
}

export function createAuthError(code: AuthErrorCode, message?: string, statusCode?: number): AuthError {
  const defaultMessages: Record<AuthErrorCode, string> = {
    [AuthErrorCode.INVALID_EMAIL]: 'Invalid email address format',
    [AuthErrorCode.EMAIL_CONFIG_MISSING]: 'Email configuration is required for magic link authentication',
    [AuthErrorCode.WEBAUTHN_CONFIG_MISSING]: 'WebAuthn configuration is required for biometric authentication',
    [AuthErrorCode.TOKEN_INVALID]: 'Invalid authentication token',
    [AuthErrorCode.TOKEN_EXPIRED]: 'Authentication token has expired',
    [AuthErrorCode.VERIFICATION_FAILED]: 'Authentication verification failed',
    [AuthErrorCode.RATE_LIMIT_EXCEEDED]: 'Too many authentication attempts, please try again later',
    [AuthErrorCode.USER_NOT_FOUND]: 'User not found',
    [AuthErrorCode.INVALID_CREDENTIALS]: 'Invalid authentication credentials'
  };

  const defaultStatusCodes: Record<AuthErrorCode, number> = {
    [AuthErrorCode.INVALID_EMAIL]: 400,
    [AuthErrorCode.EMAIL_CONFIG_MISSING]: 500,
    [AuthErrorCode.WEBAUTHN_CONFIG_MISSING]: 500,
    [AuthErrorCode.TOKEN_INVALID]: 401,
    [AuthErrorCode.TOKEN_EXPIRED]: 401,
    [AuthErrorCode.VERIFICATION_FAILED]: 401,
    [AuthErrorCode.RATE_LIMIT_EXCEEDED]: 429,
    [AuthErrorCode.USER_NOT_FOUND]: 404,
    [AuthErrorCode.INVALID_CREDENTIALS]: 401
  };

  return new AuthError(
    code,
    message || defaultMessages[code],
    statusCode || defaultStatusCodes[code]
  );
}