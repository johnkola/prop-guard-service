'use client';

import { useState } from 'react';
import { Save, X, User, Mail, Lock, Shield } from 'lucide-react';

interface UserFormData {
    username: string;
    email: string;
    password?: string;
    roles: string[];
    enabled: boolean;
}

interface UserFormProps {
    initialData?: Partial<UserFormData>;
    isEditing?: boolean;
    availableRoles?: string[];
    onSave?: (data: UserFormData) => void;
    onCancel?: () => void;
}

export default function UserForm({ 
    initialData, 
    isEditing = false, 
    availableRoles = ['role_user', 'role_admin'], 
    onSave, 
    onCancel 
}: UserFormProps) {
    const [formData, setFormData] = useState<UserFormData>({
        username: initialData?.username || '',
        email: initialData?.email || '',
        password: initialData?.password || '',
        roles: initialData?.roles || ['role_user'],
        enabled: initialData?.enabled ?? true,
    });

    const [errors, setErrors] = useState<Record<string, string>>({});
    const [showPassword, setShowPassword] = useState(false);

    const validateForm = (): boolean => {
        const newErrors: Record<string, string> = {};

        if (!formData.username.trim()) {
            newErrors.username = 'Username is required';
        } else if (formData.username.length < 3) {
            newErrors.username = 'Username must be at least 3 characters';
        }

        if (!formData.email.trim()) {
            newErrors.email = 'Email is required';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            newErrors.email = 'Please enter a valid email address';
        }

        if (!isEditing && !formData.password) {
            newErrors.password = 'Password is required';
        } else if (formData.password && formData.password.length < 8) {
            newErrors.password = 'Password must be at least 8 characters';
        }

        if (formData.roles.length === 0) {
            newErrors.roles = 'At least one role must be selected';
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!validateForm()) return;

        const submitData = { ...formData };
        
        // Don't send password if it's empty in edit mode
        if (isEditing && !submitData.password) {
            delete submitData.password;
        }

        onSave?.(submitData);
    };

    const handleRoleToggle = (role: string) => {
        setFormData(prev => ({
            ...prev,
            roles: prev.roles.includes(role) 
                ? prev.roles.filter(r => r !== role)
                : [...prev.roles, role]
        }));
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title flex items-center gap-2">
                        <User className="w-5 h-5" />
                        {isEditing ? 'Edit User' : 'Create New User'}
                    </h2>
                    {onCancel && (
                        <button 
                            className="btn btn-ghost btn-sm"
                            onClick={onCancel}
                        >
                            <X className="w-4 h-4" />
                        </button>
                    )}
                </div>

                <form onSubmit={handleSubmit} className="space-y-6">
                    {/* Username */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text flex items-center gap-2">
                                <User className="w-4 h-4" />
                                Username *
                            </span>
                        </label>
                        <input
                            type="text"
                            className={`input input-bordered ${errors.username ? 'input-error' : ''}`}
                            placeholder="Enter username"
                            value={formData.username}
                            onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                            disabled={isEditing} // Username usually can't be changed
                        />
                        {errors.username && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.username}</span>
                            </label>
                        )}
                    </div>

                    {/* Email */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text flex items-center gap-2">
                                <Mail className="w-4 h-4" />
                                Email *
                            </span>
                        </label>
                        <input
                            type="email"
                            className={`input input-bordered ${errors.email ? 'input-error' : ''}`}
                            placeholder="user@example.com"
                            value={formData.email}
                            onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                        />
                        {errors.email && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.email}</span>
                            </label>
                        )}
                    </div>

                    {/* Password */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text flex items-center gap-2">
                                <Lock className="w-4 h-4" />
                                Password {!isEditing ? '*' : '(leave empty to keep current)'}
                            </span>
                        </label>
                        <div className="input-group">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                className={`input input-bordered flex-1 ${errors.password ? 'input-error' : ''}`}
                                placeholder={isEditing ? "Enter new password" : "Enter password"}
                                value={formData.password}
                                onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                            />
                            <button
                                type="button"
                                className="btn btn-square btn-outline"
                                onClick={() => setShowPassword(!showPassword)}
                            >
                                {showPassword ? '🙈' : '👁️'}
                            </button>
                        </div>
                        {errors.password && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.password}</span>
                            </label>
                        )}
                    </div>

                    {/* Roles */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text flex items-center gap-2">
                                <Shield className="w-4 h-4" />
                                Roles *
                            </span>
                        </label>
                        <div className="flex flex-wrap gap-2 p-3 border border-base-300 rounded-lg">
                            {availableRoles.map(role => (
                                <label key={role} className="label cursor-pointer flex-nowrap gap-2">
                                    <input
                                        type="checkbox"
                                        className="checkbox checkbox-sm"
                                        checked={formData.roles.includes(role)}
                                        onChange={() => handleRoleToggle(role)}
                                    />
                                    <span className="label-text whitespace-nowrap">
                                        {role.replace('role_', '').replace('_', ' ').toUpperCase()}
                                    </span>
                                </label>
                            ))}
                        </div>
                        {errors.roles && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.roles}</span>
                            </label>
                        )}
                    </div>

                    {/* Enabled Toggle */}
                    <div className="form-control">
                        <label className="label cursor-pointer justify-start gap-3">
                            <input
                                type="checkbox"
                                className="toggle toggle-primary"
                                checked={formData.enabled}
                                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                            />
                            <div>
                                <span className="label-text font-semibold">Account Enabled</span>
                                <div className="text-xs text-base-content/70">
                                    {formData.enabled ? 'User can log in and access the system' : 'User account is disabled'}
                                </div>
                            </div>
                        </label>
                    </div>

                    {/* Actions */}
                    <div className="card-actions justify-end pt-4 border-t border-base-200">
                        {onCancel && (
                            <button type="button" className="btn btn-ghost" onClick={onCancel}>
                                Cancel
                            </button>
                        )}
                        <button type="submit" className="btn btn-primary">
                            <Save className="w-4 h-4" />
                            {isEditing ? 'Update User' : 'Create User'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}