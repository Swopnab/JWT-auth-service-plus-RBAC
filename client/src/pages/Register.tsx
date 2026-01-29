import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import toast from 'react-hot-toast';
import { useAuthStore } from '../store/auth.store';
import { UserPlus, Mail, Lock, Loader2, CheckCircle } from 'lucide-react';
import './AuthPages.css';

const registerSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[a-z]/, 'Must contain lowercase letter')
        .regex(/[A-Z]/, 'Must contain uppercase letter')
        .regex(/[0-9]/, 'Must contain number'),
    confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function Register() {
    const navigate = useNavigate();
    const registerUser = useAuthStore((state) => state.register);
    const [isLoading, setIsLoading] = useState(false);
    const [verificationLink, setVerificationLink] = useState<string | null>(null);

    const {
        register,
        handleSubmit,
        formState: { errors },
        watch,
    } = useForm<RegisterForm>({
        resolver: zodResolver(registerSchema),
    });

    const password = watch('password');

    const getPasswordStrength = () => {
        if (!password) return { label: '', color: '' };
        const strength = [
            password.length >= 8,
            /[a-z]/.test(password),
            /[A-Z]/.test(password),
            /[0-9]/.test(password),
        ].filter(Boolean).length;

        if (strength <= 2) return { label: 'Weak', color: 'var(--color-error)' };
        if (strength === 3) return { label: 'Medium', color: 'var(--color-warning)' };
        return { label: 'Strong', color: 'var(--color-success)' };
    };

    const onSubmit = async (data: RegisterForm) => {
        setIsLoading(true);
        try {
            const response = await registerUser(data.email, data.password);
            toast.success('Registration successful!');

            // In dev mode, backend returns verification link
            if (response.verificationLink) {
                setVerificationLink(response.verificationLink);
            } else {
                toast.success('Please check your email to verify your account');
                navigate('/login');
            }
        } catch (error: any) {
            const message = error.response?.data?.error?.message || 'Registration failed';
            toast.error(message);
        } finally {
            setIsLoading(false);
        }
    };

    const passwordStrength = getPasswordStrength();

    if (verificationLink) {
        return (
            <div className="auth-page">
                <div className="auth-container">
                    <div className="auth-card">
                        <div className="auth-header">
                            <CheckCircle size={48} style={{ color: 'var(--color-success)' }} />
                            <h1>Check Your Email</h1>
                            <p>We've sent a verification link to your email address</p>
                        </div>

                        <div className="alert alert-info">
                            <strong>Dev Mode:</strong> Verification link (only shown in development)
                        </div>

                        <a href={verificationLink} className="btn btn-primary btn-lg" style={{ width: '100%' }}>
                            Verify Email Now
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
                        <UserPlus size={32} className="auth-icon" />
                        <h1>Create Account</h1>
                        <p>Get started with your free account</p>
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

                        <div className="form-group">
                            <label htmlFor="password" className="form-label">
                                <Lock size={16} />
                                Password
                            </label>
                            <input
                                {...register('password')}
                                id="password"
                                type="password"
                                className={`input ${errors.password ? 'error' : ''}`}
                                placeholder="••••••••"
                                autoComplete="new-password"
                            />
                            {password && (
                                <div className="password-strength">
                                    <div className="strength-bar">
                                        <div
                                            className="strength-fill"
                                            style={{
                                                width: `${(getPasswordStrength().label === 'Weak' ? 33 : getPasswordStrength().label === 'Medium' ? 66 : 100)}%`,
                                                backgroundColor: passwordStrength.color
                                            }}
                                        />
                                    </div>
                                    <span style={{ color: passwordStrength.color, fontSize: 'var(--font-size-sm)' }}>
                                        {passwordStrength.label}
                                    </span>
                                </div>
                            )}
                            {errors.password && (
                                <span className="form-error">{errors.password.message}</span>
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
                                    Creating account...
                                </>
                            ) : (
                                'Create account'
                            )}
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>
                            Already have an account?{' '}
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
