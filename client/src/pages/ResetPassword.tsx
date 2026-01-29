import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import toast from 'react-hot-toast';
import * as authApi from '../services/auth.api';
import { Lock, Loader2 } from 'lucide-react';
import './AuthPages.css';

const resetPasswordSchema = z.object({
    newPassword: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[a-z]/, 'Must contain lowercase letter')
        .regex(/[A-Z]/, 'Must contain uppercase letter')
        .regex(/[0-9]/, 'Must contain number'),
    confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
});

type ResetPasswordForm = z.infer<typeof resetPasswordSchema>;

export default function ResetPassword() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [isLoading, setIsLoading] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<ResetPasswordForm>({
        resolver: zodResolver(resetPasswordSchema),
    });

    if (!token) {
        return (
            <div className="auth-page">
                <div className="auth-container">
                    <div className="auth-card">
                        <div className="alert alert-error">
                            <strong>Invalid Link</strong>
                            <p>This password reset link is invalid or has expired.</p>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    const onSubmit = async (data: ResetPasswordForm) => {
        setIsLoading(true);
        try {
            await authApi.resetPassword(token, data.newPassword);
            toast.success('Password reset successful!');
            navigate('/login');
        } catch (error: any) {
            const message = error.response?.data?.error?.message || 'Reset failed';
            toast.error(message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-card">
                    <div className="auth-header">
                        <Lock size={32} className="auth-icon" />
                        <h1>Reset Password</h1>
                        <p>Enter your new password</p>
                    </div>

                    <form onSubmit={handleSubmit(onSubmit)} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="newPassword" className="form-label">
                                <Lock size={16} />
                                New Password
                            </label>
                            <input
                                {...register('newPassword')}
                                id="newPassword"
                                type="password"
                                className={`input ${errors.newPassword ? 'error' : ''}`}
                                placeholder="••••••••"
                                autoComplete="new-password"
                            />
                            {errors.newPassword && (
                                <span className="form-error">{errors.newPassword.message}</span>
                            )}
                        </div>

                        <div className="form-group">
                            <label htmlFor="confirmPassword" className="form-label">
                                <Lock size={16} />
                                Confirm Password
                            </label>
                            <input
                                {...register('confirmPassword')}
                                id="confirmPassword"
                                type="password"
                                className={`input ${errors.confirmPassword ? 'error' : ''}`}
                                placeholder="••••••••"
                                autoComplete="new-password"
                            />
                            {errors.confirmPassword && (
                                <span className="form-error">{errors.confirmPassword.message}</span>
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
                                    Resetting...
                                </>
                            ) : (
                                'Reset Password'
                            )}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}
