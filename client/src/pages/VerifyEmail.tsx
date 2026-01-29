import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import * as authApi from '../services/auth.api';
import { CheckCircle, XCircle, Loader2 } from 'lucide-react';
import './AuthPages.css';

export default function VerifyEmail() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
    const [message, setMessage] = useState('');

    useEffect(() => {
        const verifyEmail = async () => {
            if (!token) {
                setStatus('error');
                setMessage('Invalid verification link');
                return;
            }

            try {
                await authApi.verifyEmail(token);
                setStatus('success');
                setMessage('Email verified successfully!');
                toast.success('Email verified!');

                // Redirect to login after 2 seconds
                setTimeout(() => {
                    navigate('/login');
                }, 2000);
            } catch (error: any) {
                setStatus('error');
                setMessage(error.response?.data?.error?.message || 'Verification failed');
                toast.error('Verification failed');
            }
        };

        verifyEmail();
    }, [token, navigate]);

    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-card">
                    <div className="auth-header">
                        {status === 'loading' && (
                            <>
                                <Loader2 size={48} className="spinner-icon" style={{ color: 'var(--color-primary)' }} />
                                <h1>Verifying Email...</h1>
                                <p>Please wait while we verify your email address</p>
                            </>
                        )}

                        {status === 'success' && (
                            <>
                                <CheckCircle size={48} style={{ color: 'var(--color-success)' }} />
                                <h1>Email Verified!</h1>
                                <p>{message}</p>
                                <div className="alert alert-success mt-lg">
                                    Redirecting to login...
                                </div>
                            </>
                        )}

                        {status === 'error' && (
                            <>
                                <XCircle size={48} style={{ color: 'var(--color-error)' }} />
                                <h1>Verification Failed</h1>
                                <p>{message}</p>
                                <button onClick={() => navigate('/login')} className="btn btn-primary mt-lg">
                                    Go to Login
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
