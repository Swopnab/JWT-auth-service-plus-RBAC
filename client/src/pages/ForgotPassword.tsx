import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import toast from 'react-hot-toast';
import * as authApi from '../services/auth.api';
import { Mail, Loader2, CheckCircle } from 'lucide-react';
import './AuthPages.css';

const forgotPasswordSchema = z.object({
    email: z.string().email('Invalid email address'),
});

type ForgotPasswordForm = z.infer<typeof forgotPasswordSchema>;

export default function ForgotPassword() {
    const [isLoading, setIsLoading] = useState(false);
    const [resetLink, setResetLink] = useState<string | null>(null);

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<ForgotPasswordForm>({
        resolver: zodResolver(forgotPasswordSchema),
    });

    const onSubmit = async (data: ForgotPasswordForm) => {
        setIsLoading(true);
        try {
            const response = await authApi.forgotPassword(data.email);
            toast.success('Password reset email sent!');

            // In dev mode, backend returns reset link
            if (response.resetLink) {
                setResetLink(response.resetLink);
            }
        } catch (error: any) {
            const message = error.response?.data?.error?.message || 'Request failed';
            toast.error(message);
        } finally {
            setIsLoading(false);
        }
    };

    if (resetLink) {
        return (
            <div className="auth-page">
                <div className="auth-container">
                    <div className="auth-card">
                        <div className="auth-header">
                            <CheckCircle size={48} style={{ color: 'var(--color-success)' }} />
                            <h1>Check Your Email</h1>
                            <p>We've sent a password reset link to your email</p>
                        </div>

                        <div className="alert alert-info">
                            <strong>Dev Mode:</strong> Reset link (only shown in development)
                        </div>

                        <a href={resetLink} className="btn btn-primary btn-lg" style={{ width: '100%' }}>
                            Reset Password Now
                        </a>

                        <div className="auth-footer">
                            <Link to="/login" className="link-primary">
                                Back to Login
                            </Link>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-card">
                    <div className="auth-header">
                        <Mail size={32} className="auth-icon" />
                        <h1>Forgot Password?</h1>
                        <p>Enter your email to receive a password reset link</p>
                    </div>

                    <form onSubmit={handleSubmit(onSubmit)} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="email" className="form-label">
                                <Mail size={16} />
                                Email Address
                            </label>
                            <input
                                {...register('email')}
                                id="email"
                                type="email"
                                className={`input ${errors.email ? 'error' : ''}`}
                                placeholder="you@example.com"
                                autoComplete="email"
                            />
                            {errors.email && (
                                <span className="form-error">{errors.email.message}</span>
                            )}
                        </div>

                        <button
                            type="submit"
                            className="btn btn-primary btn-lg"
                            disabled={isLoading}
                            style={{ width: '100%' }}
                        >
                            {isLoading ? (
                                <>
                                    <Loader2 size={20} className="spinner-icon" />
                                    Sending...
                                </>
                            ) : (
                                'Send Reset Link'
                            )}
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>
                            Remember your password?{' '}
                            <Link to="/login" className="link-primary">
                                Sign in
                            </Link>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
