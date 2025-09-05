'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, LogIn, AlertCircle } from 'lucide-react';

export default function LoginPage() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const router = useRouter();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            // Make API call to backend /api/v1/auth/login
            const response = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (response.ok && data.token) {
                // Successful login
                const userInfo = {
                    username: data.user?.username || username,
                    roles: data.user?.roles || ['user'],
                    id: data.user?.id || `user_${username}`
                };
                
                // Store in localStorage and cookies
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(userInfo));
                
                // Set cookie for middleware (httpOnly would be better in production)
                document.cookie = `token=${data.token}; path=/; max-age=${60 * 60 * 24}`; // 24 hours
                
                // Redirect to dashboard
                router.push('/');
                router.refresh();
            } else {
                setError(data.message || 'Invalid username or password');
            }
        } catch (err) {
            setError('Login failed. Please try again.');
            console.error('Login error:', err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-primary/10 via-base-200 to-secondary/10 flex items-center justify-center p-4">
            <div className="card w-full max-w-md bg-base-100 shadow-2xl">
                <div className="card-body">
                    {/* Header */}
                    <div className="text-center mb-6">
                        <div className="flex justify-center mb-4">
                            <div className="bg-primary/10 p-3 rounded-full">
                                <Shield className="h-10 w-10 text-primary" />
                            </div>
                        </div>
                        <h1 className="text-3xl font-bold text-base-content">PropGuard</h1>
                        <p className="text-base-content/70 mt-2">Secure Secrets Management</p>
                    </div>

                    {/* Error Alert */}
                    {error && (
                        <div className="alert alert-error mb-4">
                            <AlertCircle className="h-5 w-5" />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Login Form */}
                    <form onSubmit={handleSubmit} className="space-y-4">
                        {/* Username Field */}
                        <div className="form-control">
                            <label className="label">
                                <span className="label-text font-medium">Username</span>
                            </label>
                            <input
                                type="text"
                                placeholder="Enter your username"
                                className="input input-bordered w-full"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                required
                                disabled={loading}
                                autoComplete="username"
                            />
                        </div>

                        {/* Password Field */}
                        <div className="form-control">
                            <label className="label">
                                <span className="label-text font-medium">Password</span>
                            </label>
                            <div className="relative">
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="Enter your password"
                                    className="input input-bordered w-full pr-12"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                    disabled={loading}
                                    autoComplete="current-password"
                                />
                                <button
                                    type="button"
                                    className="absolute right-3 top-1/2 transform -translate-y-1/2 btn btn-ghost btn-sm btn-square"
                                    onClick={() => setShowPassword(!showPassword)}
                                    disabled={loading}
                                >
                                    {showPassword ? (
                                        <EyeOff className="h-4 w-4" />
                                    ) : (
                                        <Eye className="h-4 w-4" />
                                    )}
                                </button>
                            </div>
                        </div>

                        {/* Submit Button */}
                        <div className="form-control mt-6">
                            <button
                                type="submit"
                                className={`btn btn-primary w-full ${loading ? 'loading' : ''}`}
                                disabled={loading || !username || !password}
                            >
                                {!loading && <LogIn className="h-5 w-5 mr-2" />}
                                {loading ? 'Signing in...' : 'Sign In'}
                            </button>
                        </div>
                    </form>


                    {/* Footer */}
                    <div className="text-center mt-6 pt-4 border-t border-base-300">
                        <p className="text-xs text-base-content/50">
                            © 2025 PropGuard - Secure by Design
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}