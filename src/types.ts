export interface AuthConfig {
  jwtSecret: string;
  jwtExpiry?: string;
  emailConfig?: EmailConfig;
  webauthnConfig?: WebAuthnConfig;
}

export interface EmailConfig {
  host: string;
  port: number;
  secure?: boolean;
  user: string;
  pass: string;
  fromEmail: string;
  fromName?: string;
}

export interface WebAuthnConfig {
  rpName: string;
  rpId: string;
  origin: string;
}

export interface MagicLinkOptions {
  email: string;
  redirectUrl?: string;
  expiresIn?: number;
}

export interface AuthResult {
  success: boolean;
  token?: string;
  error?: string;
  user?: UserInfo;
}

export interface UserInfo {
  id: string;
  email: string;
  createdAt: Date;
  lastLogin?: Date;
}

export interface VerifyTokenResult {
  valid: boolean;
  payload?: any;
  error?: string;
}