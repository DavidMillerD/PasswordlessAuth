const { PasswordlessAuth } = require('../dist');

const auth = new PasswordlessAuth({
  jwtSecret: 'demo-secret-key-change-in-production',
  emailConfig: {
    host: 'smtp.ethereal.email',
    port: 587,
    user: 'test@ethereal.email',
    pass: 'password123',
    fromEmail: 'noreply@example.com',
    fromName: 'Demo App'
  }
});

async function demo() {
  try {
    // Send magic link
    console.log('Sending magic link...');
    const result = await auth.sendMagicLink({
      email: 'demo@example.com',
      redirectUrl: 'http://localhost:3000/auth'
    });
    
    if (result.success) {
      console.log('Magic link sent successfully!');
    } else {
      console.error('Failed to send magic link:', result.error);
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

demo();