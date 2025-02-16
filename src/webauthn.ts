import { WebAuthnConfig } from './types';
import { generateSecureToken } from './utils';

export interface CredentialCreationOptions {
  publicKey: PublicKeyCredentialCreationOptions;
}

export interface CredentialRequestOptions {
  publicKey: PublicKeyCredentialRequestOptions;
}

export class WebAuthnAuth {
  constructor(private config: WebAuthnConfig) {}

  generateRegistrationOptions(userId: string, userName: string, userDisplayName: string): CredentialCreationOptions {
    const challenge = new Uint8Array(
      Buffer.from(generateSecureToken(32), 'hex')
    );

    const user = {
      id: new Uint8Array(Buffer.from(userId, 'utf-8')),
      name: userName,
      displayName: userDisplayName
    };

    return {
      publicKey: {
        rp: {
          name: this.config.rpName,
          id: this.config.rpId
        },
        user,
        challenge,
        pubKeyCredParams: [
          { alg: -7, type: "public-key" },  // ES256
          { alg: -257, type: "public-key" }  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "preferred"
        },
        timeout: 60000,
        attestation: "direct"
      }
    };
  }

  generateAuthenticationOptions(allowCredentials?: PublicKeyCredentialDescriptor[]): CredentialRequestOptions {
    const challenge = new Uint8Array(
      Buffer.from(generateSecureToken(32), 'hex')
    );

    return {
      publicKey: {
        challenge,
        timeout: 60000,
        rpId: this.config.rpId,
        allowCredentials: allowCredentials || [],
        userVerification: "preferred"
      }
    };
  }

  async verifyRegistration(credential: PublicKeyCredential): Promise<{ verified: boolean; error?: string }> {
    try {
      const response = credential.response as AuthenticatorAttestationResponse;
      
      if (!response.clientDataJSON || !response.attestationObject) {
        return { verified: false, error: 'Missing credential data' };
      }

      const clientDataJSON = JSON.parse(
        Buffer.from(response.clientDataJSON).toString('utf8')
      );

      if (clientDataJSON.type !== 'webauthn.create') {
        return { verified: false, error: 'Invalid credential type' };
      }

      if (clientDataJSON.origin !== this.config.origin) {
        return { verified: false, error: 'Invalid origin' };
      }

      return { verified: true };
    } catch (error) {
      return { verified: false, error: 'Verification failed' };
    }
  }

  async verifyAuthentication(credential: PublicKeyCredential): Promise<{ verified: boolean; error?: string }> {
    try {
      const response = credential.response as AuthenticatorAssertionResponse;
      
      if (!response.clientDataJSON || !response.authenticatorData || !response.signature) {
        return { verified: false, error: 'Missing authentication data' };
      }

      const clientDataJSON = JSON.parse(
        Buffer.from(response.clientDataJSON).toString('utf8')
      );

      if (clientDataJSON.type !== 'webauthn.get') {
        return { verified: false, error: 'Invalid authentication type' };
      }

      if (clientDataJSON.origin !== this.config.origin) {
        return { verified: false, error: 'Invalid origin' };
      }

      return { verified: true };
    } catch (error) {
      return { verified: false, error: 'Authentication failed' };
    }
  }
}