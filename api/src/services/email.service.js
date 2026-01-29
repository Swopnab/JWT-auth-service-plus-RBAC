// Email service - handles email sending (mock for now)
// Vanilla JavaScript version

/**
 * Simple console-based email service for development
 * In production, integrate with a real email service (SendGrid, AWS  SES, etc.)
 */
export class EmailService {
    /**
     * @param {Object} env - Cloudflare environment bindings
     */
    constructor(env) {
        this.env = env;
    }

    /**
     * Send verification email
     * @param {string} email - Recipient email
     * @param {string} token - Verification token
     * @returns {Promise<void>}
     */
    async sendVerificationEmail(email, token) {
        const verificationUrl = `${this.env.FRONTEND_URL}/verify-email?token=${token}`;

        console.log('📧 [EMAIL] Verification Email');
        console.log(`To: ${email}`);
        console.log(`Verification URL: ${verificationUrl}`);
        console.log('---');

        // In production: integrate with real email service
        // await sendgrid.send({ to: email, template: 'verify', data: { verificationUrl } });
    }

    /**
     * Send password reset email
     * @param {string} email - Recipient email
     * @param {string} token - Reset token
     * @returns {Promise<void>}
     */
    async sendPasswordResetEmail(email, token) {
        const resetUrl = `${this.env.FRONTEND_URL}/reset-password?token=${token}`;

        console.log('📧 [EMAIL] Password Reset Email');
        console.log(`To: ${email}`);
        console.log(`Reset URL: ${resetUrl}`);
        console.log('---');

        // In production: integrate with real email service
        // await sendgrid.send({ to: email, template: 'reset', data: { resetUrl } });
    }

    /**
     * Send welcome email
     * @param {string} email - Recipient email
     * @param {string} name - User name
     * @returns {Promise<void>}
     */
    async sendWelcomeEmail(email, name) {
        console.log('📧 [EMAIL] Welcome Email');
        console.log(`To: ${email}`);
        console.log(`Hello ${name || email}, welcome to Auth Service!`);
        console.log('---');

        // In production: integrate with real email service
        // await sendgrid.send({ to: email, template: 'welcome', data: { name } });
    }
}
