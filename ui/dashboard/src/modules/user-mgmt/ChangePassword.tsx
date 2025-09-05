'use client';

import { useState } from 'react';
import { Eye, EyeOff, Lock, CheckCircle, XCircle, Key } from 'lucide-react';
import { ApiClient } from '../../lib/api';

interface ChangePasswordProps {
    userId?: string;
    onSuccess?: () => void;
    onCancel?: () => void;
}

export default function ChangePassword({ userId, onSuccess, onCancel }: ChangePasswordProps) {
    const [formData, setFormData] = useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [showPasswords, setShowPasswords] = useState({
        current: false,
        new: false,
        confirm: false
    });
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    // Password strength validation
    const getPasswordStrength = (password: string) => {
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
        
        if (score < 2) return { level: 'weak', color: 'error', text: 'Weak' };
        if (score < 4) return { level: 'medium', color: 'warning', text: 'Medium' };
        return { level: 'strong', color: 'success', text: 'Strong' };
    };

    const passwordStrength = getPasswordStrength(formData.newPassword);
    const passwordsMatch = formData.newPassword === formData.confirmPassword;
    const isFormValid = formData.currentPassword && 
                       formData.newPassword.length >= 8 && 
                       passwordsMatch;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!isFormValid) return;

        setIsLoading(true);
        setError('');

        try {
            const response = await ApiClient.put(`/users/${userId || 'me'}/password`, {
                currentPassword: formData.currentPassword,
                newPassword: formData.newPassword
            });

            if (response.error) {
                setError(response.error);
            } else {
                setSuccess(true);
                setTimeout(() => {
                    onSuccess?.();
                }, 2000);
            }
        } catch (error) {
            setError('Failed to change password. Please try again.');
            console.error('Password change error:', error);
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
        if (success) setSuccess(false);
    };

    const togglePasswordVisibility = (field: 'current' | 'new' | 'confirm') => {
        setShowPasswords(prev => ({
            ...prev,
            [field]: !prev[field]
        }));
    };

    if (success) {
        return (
            <div className="card bg-base-100 shadow-xl max-w-md mx-auto">
                <div className="card-body text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 rounded-full bg-success/20">
                            <CheckCircle className="w-8 h-8 text-success" />
                        </div>
                    </div>
                    <h2 className="card-title text-2xl justify-center">
                        Password Changed!
                    </h2>
                    <p className="text-base-content/70 mt-2">
                        Your password has been successfully updated.
                    </p>
                    <div className="card-actions justify-center mt-6">
                        <button 
                            className="btn btn-primary"
                            onClick={onSuccess}
                        >
                            Continue
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="card bg-base-100 shadow-xl max-w-md mx-auto">
            <div className="card-body">
                <div className="text-center mb-6">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 rounded-full bg-primary/10">
                            <Key className="w-8 h-8 text-primary" />
                        </div>
                    </div>
                    <h2 className="card-title text-2xl font-bold justify-center">
                        Change Password
                    </h2>
                    <p className="text-base-content/60 mt-2">
                        Update your account password for security
                    </p>
                </div>

                {error && (
                    <div className="alert alert-error mb-4">
                        <XCircle className="w-5 h-5" />
                        <span className="text-sm">{error}</span>
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
                    {/* Current Password Field */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text font-medium">Current Password</span>
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.current ? "text" : "password"}
                                name="currentPassword"
                                placeholder="Enter your current password"
                                className="input input-bordered w-full pl-12 pr-12 focus:input-primary"
                                required
                                value={formData.currentPassword}
                                onChange={handleInputChange}
                                disabled={isLoading}
                            />
                            <Lock className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-base-content/50" />
                            <button
                                type="button"
                                className="absolute right-4 top-1/2 transform -translate-y-1/2 text-base-content/50 hover:text-base-content transition-colors"
                                onClick={() => togglePasswordVisibility('current')}
                                disabled={isLoading}
                            >
                                {showPasswords.current ?
                                    <EyeOff className="w-5 h-5" /> :
                                    <Eye className="w-5 h-5" />
                                }
                            </button>
                        </div>
                    </div>

                    {/* New Password Field */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text font-medium">New Password</span>
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.new ? "text" : "password"}
                                name="newPassword"
                                placeholder="Enter your new password"
                                className="input input-bordered w-full pl-12 pr-12 focus:input-primary"
                                required
                                minLength={8}
                                value={formData.newPassword}
                                onChange={handleInputChange}
                                disabled={isLoading}
                            />
                            <Lock className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-base-content/50" />
                            <button
                                type="button"
                                className="absolute right-4 top-1/2 transform -translate-y-1/2 text-base-content/50 hover:text-base-content transition-colors"
                                onClick={() => togglePasswordVisibility('new')}
                                disabled={isLoading}
                            >
                                {showPasswords.new ?
                                    <EyeOff className="w-5 h-5" /> :
                                    <Eye className="w-5 h-5" />
                                }
                            </button>
                        </div>
                        
                        {/* Password Strength Indicator */}
                        {formData.newPassword && (
                            <div className="mt-2">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-base-content/60">Password strength:</span>
                                    <span className={`text-xs font-medium text-${passwordStrength.color}`}>
                                        {passwordStrength.text}
                                    </span>
                                </div>
                                <progress 
                                    className={`progress progress-${passwordStrength.color} w-full h-1 mt-1`} 
                                    value={passwordStrength.level === 'weak' ? 33 : passwordStrength.level === 'medium' ? 66 : 100} 
                                    max="100"
                                />
                            </div>
                        )}
                    </div>

                    {/* Confirm Password Field */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text font-medium">Confirm New Password</span>
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.confirm ? "text" : "password"}
                                name="confirmPassword"
                                placeholder="Confirm your new password"
                                className={`input input-bordered w-full pl-12 pr-12 focus:input-primary ${
                                    formData.confirmPassword && !passwordsMatch ? 'input-error' : ''
                                }`}
                                required
                                value={formData.confirmPassword}
                                onChange={handleInputChange}
                                disabled={isLoading}
                            />
                            <Lock className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-base-content/50" />
                            <button
                                type="button"
                                className="absolute right-4 top-1/2 transform -translate-y-1/2 text-base-content/50 hover:text-base-content transition-colors"
                                onClick={() => togglePasswordVisibility('confirm')}
                                disabled={isLoading}
                            >
                                {showPasswords.confirm ?
                                    <EyeOff className="w-5 h-5" /> :
                                    <Eye className="w-5 h-5" />
                                }
                            </button>
                        </div>
                        {formData.confirmPassword && !passwordsMatch && (
                            <label className="label">
                                <span className="label-text-alt text-error">Passwords do not match</span>
                            </label>
                        )}
                    </div>

                    {/* Password Requirements */}
                    <div className="text-sm text-base-content/60 bg-base-200 p-3 rounded-lg">
                        <h4 className="font-medium mb-2">Password requirements:</h4>
                        <ul className="space-y-1">
                            <li className={`flex items-center ${formData.newPassword.length >= 8 ? 'text-success' : ''}`}>
                                <CheckCircle className={`w-3 h-3 mr-2 ${formData.newPassword.length >= 8 ? 'text-success' : 'text-base-content/40'}`} />
                                At least 8 characters
                            </li>
                            <li className={`flex items-center ${/[A-Z]/.test(formData.newPassword) ? 'text-success' : ''}`}>
                                <CheckCircle className={`w-3 h-3 mr-2 ${/[A-Z]/.test(formData.newPassword) ? 'text-success' : 'text-base-content/40'}`} />
                                One uppercase letter
                            </li>
                            <li className={`flex items-center ${/[a-z]/.test(formData.newPassword) ? 'text-success' : ''}`}>
                                <CheckCircle className={`w-3 h-3 mr-2 ${/[a-z]/.test(formData.newPassword) ? 'text-success' : 'text-base-content/40'}`} />
                                One lowercase letter
                            </li>
                            <li className={`flex items-center ${/\d/.test(formData.newPassword) ? 'text-success' : ''}`}>
                                <CheckCircle className={`w-3 h-3 mr-2 ${/\d/.test(formData.newPassword) ? 'text-success' : 'text-base-content/40'}`} />
                                One number
                            </li>
                        </ul>
                    </div>

                    {/* Action Buttons */}
                    <div className="form-control">
                        <div className="flex gap-3">
                            {onCancel && (
                                <button
                                    type="button"
                                    className="btn btn-ghost flex-1"
                                    onClick={onCancel}
                                    disabled={isLoading}
                                >
                                    Cancel
                                </button>
                            )}
                            <button
                                className={`btn btn-primary flex-1 ${!onCancel ? 'w-full' : ''}`}
                                type="submit"
                                disabled={!isFormValid || isLoading}
                            >
                                {isLoading ? (
                                    <span className="loading loading-spinner loading-sm"></span>
                                ) : (
                                    <Key className="w-5 h-5 mr-2" />
                                )}
                                {isLoading ? 'Changing...' : 'Change Password'}
                            </button>
                        </div>
                    </div>
                </form>

                <div className="divider text-sm opacity-50">Security Notice</div>

                <div className="text-center text-sm text-base-content/60">
                    <p>Your password will be encrypted and securely stored.</p>
                    <div className="flex justify-center space-x-2 mt-2">
                        <div className="badge badge-outline badge-xs">AES-256</div>
                        <div className="badge badge-outline badge-xs">Encrypted</div>
                        <div className="badge badge-outline badge-xs">Audited</div>
                    </div>
                </div>
            </div>
        </div>
    );
}