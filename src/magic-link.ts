import * as nodemailer from 'nodemailer';
import { EmailConfig, MagicLinkOptions } from './types';
import { generateSecureToken, isValidEmail } from './utils';

export class MagicLinkAuth {
  private transporter: nodemailer.Transporter | null = null;
  private pendingTokens = new Map<string, { email: string; expiresAt: number }>();

  constructor(private emailConfig?: EmailConfig) {
    if (emailConfig) {
      this.transporter = nodemailer.createTransporter({
        host: emailConfig.host,
        port: emailConfig.port,
        secure: emailConfig.secure || false,
        auth: {
          user: emailConfig.user,
          pass: emailConfig.pass
        }
      });
    }
  }

  async sendMagicLink(options: MagicLinkOptions): Promise<{ success: boolean; token?: string; error?: string }> {
    if (!isValidEmail(options.email)) {
      return { success: false, error: 'Invalid email address' };
    }

    if (!this.transporter) {
      return { success: false, error: 'Email configuration not provided' };
    }

    const token = generateSecureToken();
    const expiresIn = options.expiresIn || 3600000; // 1 hour default
    const expiresAt = Date.now() + expiresIn;

    this.pendingTokens.set(token, {
      email: options.email,
      expiresAt
    });

    const magicLink = `${options.redirectUrl || 'http://localhost:3000/auth'}?token=${token}`;
    
    try {
      await this.transporter.sendMail({
        from: `${this.emailConfig?.fromName || 'Auth'} <${this.emailConfig?.fromEmail}>`,
        to: options.email,
        subject: 'Your magic link',
        html: `
          <h2>Sign in to your account</h2>
          <p>Click the link below to sign in:</p>
          <a href="${magicLink}" style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;">Sign In</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, you can safely ignore this email.</p>
        `
      });

      return { success: true, token };
    } catch (error) {
      return { success: false, error: 'Failed to send email' };
    }
  }

  verifyMagicToken(token: string): { valid: boolean; email?: string; error?: string } {
    const tokenData = this.pendingTokens.get(token);
    
    if (!tokenData) {
      return { valid: false, error: 'Invalid token' };
    }

    if (Date.now() > tokenData.expiresAt) {
      this.pendingTokens.delete(token);
      return { valid: false, error: 'Token expired' };
    }

    this.pendingTokens.delete(token);
    return { valid: true, email: tokenData.email };
  }

  cleanup() {
    const now = Date.now();
    for (const [token, data] of this.pendingTokens.entries()) {
      if (now > data.expiresAt) {
        this.pendingTokens.delete(token);
      }
    }
  }
}