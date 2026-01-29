import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import toast from 'react-hot-toast';
import * as authApi from '../services/auth.api';
import { Lock, Loader2 } from 'lucide-react';

const changePasswordSchema = z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
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

type ChangePasswordForm = z.infer<typeof changePasswordSchema>;

export default function ChangePassword() {
    const [isLoading, setIsLoading] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
        reset,
    } = useForm<ChangePasswordForm>({
        resolver: zodResolver(changePasswordSchema),
    });

    const onSubmit = async (data: ChangePasswordForm) => {
        setIsLoading(true);
        try {
            await authApi.changePassword(data.currentPassword, data.newPassword);
            toast.success('Password changed successfully!');
            reset();
        } catch (error: any) {
            const message = error.response?.data?.error?.message || 'Failed to change password';
            toast.error(message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div>
            <div className="mb-xl">
                <h1>Change Password</h1>
                <p className="text-secondary">Update your password to keep your account secure</p>
            </div>

            <div className="card" style={{ maxWidth: '600px' }}>
                <form onSubmit={handleSubmit(onSubmit)}>
                    <div className="form-group">
                        <label htmlFor="currentPassword" className="form-label">
                            <Lock size={16} />
                            Current Password
                        </label>
                        <input
                            {...register('currentPassword')}
                            id="currentPassword"
                            type="password"
                            className={`input ${errors.currentPassword ? 'error' : ''}`}
                            placeholder="••••••••"
                            autoComplete="current-password"
                        />
                        {errors.currentPassword && (
                            <span className="form-error">{errors.currentPassword.message}</span>
                        )}
                    </div>

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
                            Confirm New Password
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
                        className="btn btn-primary"
                        disabled={isLoading}
                    >
                        {isLoading ? (
                            <>
                                <Loader2 size={16} className="spinner-icon" />
                                Changing Password...
                            </>
                        ) : (
                            'Change Password'
                        )}
                    </button>
                </form>
            </div>
        </div>
    );
}
