'use client';

import { useState } from 'react';
import { Eye, EyeOff, Shield, Lock, User, LogIn, Home } from 'lucide-react';
import { ApiClient } from '../../lib/api';

interface LoginProps {
    onLogin: (token: string) => void;
}

export default function Login({ onLogin }: LoginProps) {
    const [formData, setFormData] = useState({
        username: '',
        password: ''
    });
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');

        try {
            // Call real authentication API
            const response = await ApiClient.login(formData.username, formData.password);
            
            if (response.data && response.data.token) {
                // Store token in localStorage
                localStorage.setItem('token', response.data.token);
                
                // Call parent onLogin with real token
                onLogin(response.data.token);
            } else {
                setError(response.error || 'Login failed. Please check your credentials.');
            }
        } catch (error) {
            setError('Login failed. Please try again.');
            console.error('Login error:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
        // Clear error when user starts typing
        if (error) setError('');
    };

    return (
        <div className="hero min-h-screen gradient-bg">
            <div className="hero-overlay bg-black bg-opacity-20"></div>
            <div className="hero-content flex-col lg:flex-row-reverse z-10 max-w-6xl p-6">

                {/* Left Side - Branding */}
                <div className="text-center lg:text-left lg:w-1/2">
                    <div className="flex items-center justify-center lg:justify-start mb-6">
                        <div className="avatar">
                            <div className="w-16 rounded-full bg-primary/20 flex items-center justify-center backdrop-blur-sm border border-white/20">
                                <Home className="w-8 h-8 text-primary" />
                            </div>
                        </div>
                        <h1 className="text-4xl lg:text-6xl font-bold text-white ml-4">
                            PropGuard
                        </h1>
                    </div>

                    <p className="text-xl text-white/90 leading-relaxed max-w-lg mb-8">
                        Smart property management system with intelligent automation, comprehensive analytics, and seamless tenant management.
                    </p>

                    <div className="space-y-4">
                        <div className="flex items-center text-white/80">
                            <div className="badge badge-success badge-sm mr-3"></div>
                            <span>Advanced Analytics Dashboard</span>
                        </div>
                        <div className="flex items-center text-white/80">
                            <div className="badge badge-success badge-sm mr-3"></div>
                            <span>Automated Rent Collection</span>
                        </div>
                        <div className="flex items-center text-white/80">
                            <div className="badge badge-success badge-sm mr-3"></div>
                            <span>Maintenance Request System</span>
                        </div>
                        <div className="flex items-center text-white/80">
                            <div className="badge badge-success badge-sm mr-3"></div>
                            <span>Tenant Portal Integration</span>
                        </div>
                    </div>
                </div>

                {/* Right Side - Login Form */}
                <div className="lg:w-1/2 w-full max-w-md">
                    <div className="card shadow-2xl bg-base-100/95 backdrop-blur-sm border border-white/20">
                        <div className="card-body">
                            <div className="text-center mb-6">
                                <div className="flex justify-center mb-4">
                                    <div className="p-3 rounded-full bg-primary/10">
                                        <Shield className="w-8 h-8 text-primary" />
                                    </div>
                                </div>
                                <h2 className="card-title text-2xl font-bold justify-center">
                                    Welcome Back
                                </h2>
                                <p className="text-base-content/60 mt-2">
                                    Sign in to access your property dashboard
                                </p>
                            </div>

                            {error && (
                                <div className="alert alert-error mb-4">
                                    <span className="text-sm">{error}</span>
                                </div>
                            )}

                            {/* Default Credentials Helper */}
                            <div className="alert alert-warning mb-4">
                                <div className="text-sm">
                                    <strong>Default Admin Credentials:</strong>
                                    <br />Username: admin
                                    <br />Password: admin123
                                    <br /><em>⚠️ Change password after first login</em>
                                </div>
                            </div>

                            <form onSubmit={handleSubmit} className="space-y-6">
                                {/* Username Field */}
                                <div className="form-control">
                                    <label className="label">
                                        <span className="label-text font-medium">Username</span>
                                    </label>
                                    <div className="relative">
                                        <input
                                            type="text"
                                            name="username"
                                            placeholder="Enter your username"
                                            className="input input-bordered w-full pl-12 focus:input-primary"
                                            required
                                            value={formData.username}
                                            onChange={handleInputChange}
                                            disabled={isLoading}
                                        />
                                        <User className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-base-content/50" />
                                    </div>
                                </div>

                                {/* Password Field */}
                                <div className="form-control">
                                    <label className="label">
                                        <span className="label-text font-medium">Password</span>
                                    </label>
                                    <div className="relative">
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            name="password"
                                            placeholder="Enter your password"
                                            className="input input-bordered w-full pl-12 pr-12 focus:input-primary"
                                            required
                                            value={formData.password}
                                            onChange={handleInputChange}
                                            disabled={isLoading}
                                        />
                                        <Lock className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-base-content/50" />
                                        <button
                                            type="button"
                                            className="absolute right-4 top-1/2 transform -translate-y-1/2 text-base-content/50 hover:text-base-content transition-colors"
                                            onClick={() => setShowPassword(!showPassword)}
                                            disabled={isLoading}
                                        >
                                            {showPassword ?
                                                <EyeOff className="w-5 h-5" /> :
                                                <Eye className="w-5 h-5" />
                                            }
                                        </button>
                                    </div>
                                </div>

                                {/* Remember Me */}
                                <div className="form-control">
                                    <label className="label cursor-pointer">
                                        <span className="label-text">Remember me</span>
                                        <input type="checkbox" className="checkbox checkbox-primary" />
                                    </label>
                                </div>

                                {/* Submit Button */}
                                <div className="form-control">
                                    <button
                                        className="btn btn-primary btn-lg w-full"
                                        type="submit"
                                        disabled={isLoading || !formData.username || !formData.password}
                                    >
                                        {isLoading ? (
                                            <span className="loading loading-spinner loading-sm"></span>
                                        ) : (
                                            <LogIn className="w-5 h-5 mr-2" />
                                        )}
                                        {isLoading ? 'Signing In...' : 'Sign In to Dashboard'}
                                    </button>
                                </div>
                            </form>

                            <div className="divider text-sm opacity-50">Secure Access</div>

                            <div className="text-center text-sm text-base-content/60">
                                <p>Protected by enterprise-grade security</p>
                                <div className="flex justify-center space-x-2 mt-3">
                                    <div className="badge badge-outline badge-xs">Multi-Tenant</div>
                                    <div className="badge badge-outline badge-xs">Cloud-Ready</div>
                                    <div className="badge badge-outline badge-xs">Real-time</div>
                                </div>

                                <div className="mt-4 pt-4 border-t border-base-300">
                                    <a href="#" className="link link-primary text-xs">
                                        Forgot your password?
                                    </a>
                                    <span className="mx-2 text-base-content/30">•</span>
                                    <a href="#" className="link link-primary text-xs">
                                        Request Demo
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}