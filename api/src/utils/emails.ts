// Email template generation utilities

// For development, we'll return the link/token directly
// In production, you'd integrate with an email service like SendGrid, Mailgun, etc.

export interface EmailTemplate {
    to: string;
    subject: string;
    html: string;
    text: string;
}

export function generateVerificationEmail(
    email: string,
    token: string,
    frontendUrl: string
): EmailTemplate {
    const verificationLink = `${frontendUrl}/verify-email?token=${token}`;

    return {
        to: email,
        subject: 'Verify your email address',
        html: `
      <h1>Welcome to Auth Service!</h1>
      <p>Please click the link below to verify your email address:</p>
      <p><a href="${verificationLink}">${verificationLink}</a></p>
      <p>This link will expire in 24 hours.</p>
      <p>If you didn't create an account, you can safely ignore this email.</p>
    `,
        text: `
      Welcome to Auth Service!
      
      Please visit the link below to verify your email address:
      ${verificationLink}
      
      This link will expire in 24 hours.
      
      If you didn't create an account, you can safely ignore this email.
    `,
    };
}

export function generatePasswordResetEmail(
    email: string,
    token: string,
    frontendUrl: string
): EmailTemplate {
    const resetLink = `${frontendUrl}/reset-password?token=${token}`;

    return {
        to: email,
        subject: 'Reset your password',
        html: `
      <h1>Password Reset Request</h1>
      <p>We received a request to reset your password. Click the link below to create a new password:</p>
      <p><a href="${resetLink}">${resetLink}</a></p>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request a password reset, you can safely ignore this email.</p>
    `,
        text: `
      Password Reset Request
      
      We received a request to reset your password. Visit the link below to create a new password:
      ${resetLink}
      
      This link will expire in 1 hour.
      
      If you didn't request a password reset, you can safely ignore this email.
    `,
    };
}

// In development mode, we return the email details for logging
export function sendEmailDev(email: EmailTemplate): { success: boolean; link?: string } {
    console.log('📧 Email (DEV MODE):', {
        to: email.to,
        subject: email.subject,
        content: email.text,
    });

    // Extract the link from the text
    const linkMatch = email.text.match(/https?:\/\/[^\s]+/);
    const link = linkMatch ? linkMatch[0] : undefined;

    return {
        success: true,
        link,
    };
}

// Placeholder for production email sending
export async function sendEmailProd(email: EmailTemplate): Promise<void> {
    // TODO: Integrate with email service (SendGrid, Mailgun, etc.)
    // Example:
    // await sendgrid.send({
    //   to: email.to,
    //   from: 'noreply@authservice.com',
    //   subject: email.subject,
    //   html: email.html,
    //   text: email.text,
    // });

    throw new Error('Email sending not configured for production');
}
