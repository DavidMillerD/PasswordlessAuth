# PasswordlessAuth

A modern TypeScript library for passwordless authentication supporting magic links and WebAuthn biometric authentication.

## Features

- 🔗 Magic link authentication via email
- 🔐 WebAuthn biometric authentication (fingerprint, face ID)
- 🎫 JWT token management
- 📧 Email integration with nodemailer
- 🔒 Secure token generation and validation

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

## License

MIT