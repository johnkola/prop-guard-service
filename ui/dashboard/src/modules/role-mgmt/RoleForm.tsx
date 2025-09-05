'use client';

import { useState } from 'react';
import { Save, X, Shield, Key, Lock } from 'lucide-react';

interface RoleFormData {
    name: string;
    description: string;
    permissions: string[];
}

interface RoleFormProps {
    initialData?: Partial<RoleFormData>;
    isEditing?: boolean;
    availablePermissions?: { id: string; name: string; category: string; description: string; }[];
    onSave?: (data: RoleFormData) => void;
    onCancel?: () => void;
}

const defaultPermissions = [
    // Secret permissions
    { id: 'secret:create', name: 'Create Secrets', category: 'Secrets', description: 'Create new secrets' },
    { id: 'secret:read', name: 'Read Secrets', category: 'Secrets', description: 'View secret values' },
    { id: 'secret:update', name: 'Update Secrets', category: 'Secrets', description: 'Modify existing secrets' },
    { id: 'secret:delete', name: 'Delete Secrets', category: 'Secrets', description: 'Remove secrets' },
    { id: 'secret:list', name: 'List Secrets', category: 'Secrets', description: 'View secret paths and metadata' },
    
    // User permissions
    { id: 'user:create', name: 'Create Users', category: 'Users', description: 'Create new user accounts' },
    { id: 'user:read', name: 'Read Users', category: 'Users', description: 'View user information' },
    { id: 'user:update', name: 'Update Users', category: 'Users', description: 'Modify user accounts' },
    { id: 'user:delete', name: 'Delete Users', category: 'Users', description: 'Remove user accounts' },
    { id: 'user:list', name: 'List Users', category: 'Users', description: 'View all users' },
    
    // Role permissions
    { id: 'role:create', name: 'Create Roles', category: 'Roles', description: 'Create new roles' },
    { id: 'role:read', name: 'Read Roles', category: 'Roles', description: 'View role information' },
    { id: 'role:update', name: 'Update Roles', category: 'Roles', description: 'Modify roles' },
    { id: 'role:delete', name: 'Delete Roles', category: 'Roles', description: 'Remove roles' },
    { id: 'role:list', name: 'List Roles', category: 'Roles', description: 'View all roles' },
    { id: 'role:assign', name: 'Assign Roles', category: 'Roles', description: 'Assign roles to users' },
    
    // Audit permissions
    { id: 'audit:read', name: 'Read Audit Logs', category: 'Audit', description: 'View audit log entries' },
    { id: 'audit:export', name: 'Export Audit Logs', category: 'Audit', description: 'Export audit data' },
    
    // System permissions
    { id: 'system:config', name: 'System Config', category: 'System', description: 'Modify system configuration' },
    { id: 'system:health', name: 'System Health', category: 'System', description: 'View system health status' },
];

export default function RoleForm({ 
    initialData, 
    isEditing = false, 
    availablePermissions = defaultPermissions, 
    onSave, 
    onCancel 
}: RoleFormProps) {
    const [formData, setFormData] = useState<RoleFormData>({
        name: initialData?.name || '',
        description: initialData?.description || '',
        permissions: initialData?.permissions || [],
    });

    const [errors, setErrors] = useState<Record<string, string>>({});

    const validateForm = (): boolean => {
        const newErrors: Record<string, string> = {};

        if (!formData.name.trim()) {
            newErrors.name = 'Role name is required';
        } else if (formData.name.length < 3) {
            newErrors.name = 'Role name must be at least 3 characters';
        }

        if (!formData.description.trim()) {
            newErrors.description = 'Description is required';
        }

        if (formData.permissions.length === 0) {
            newErrors.permissions = 'At least one permission must be selected';
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!validateForm()) return;

        onSave?.(formData);
    };

    const handlePermissionToggle = (permissionId: string) => {
        setFormData(prev => ({
            ...prev,
            permissions: prev.permissions.includes(permissionId) 
                ? prev.permissions.filter(p => p !== permissionId)
                : [...prev.permissions, permissionId]
        }));
    };

    const handleSelectAllInCategory = (category: string) => {
        const categoryPermissions = availablePermissions
            .filter(p => p.category === category)
            .map(p => p.id);
        
        const allSelected = categoryPermissions.every(p => formData.permissions.includes(p));
        
        if (allSelected) {
            // Deselect all in category
            setFormData(prev => ({
                ...prev,
                permissions: prev.permissions.filter(p => !categoryPermissions.includes(p))
            }));
        } else {
            // Select all in category
            setFormData(prev => ({
                ...prev,
                permissions: [...new Set([...prev.permissions, ...categoryPermissions])]
            }));
        }
    };

    // Group permissions by category
    const permissionsByCategory = availablePermissions.reduce((acc, permission) => {
        if (!acc[permission.category]) {
            acc[permission.category] = [];
        }
        acc[permission.category].push(permission);
        return acc;
    }, {} as Record<string, typeof availablePermissions>);

    const getCategoryIcon = (category: string) => {
        switch (category.toLowerCase()) {
            case 'secrets': return <Key className="w-4 h-4" />;
            case 'users': return <Shield className="w-4 h-4" />;
            case 'roles': return <Shield className="w-4 h-4" />;
            case 'audit': return <Lock className="w-4 h-4" />;
            case 'system': return <Lock className="w-4 h-4" />;
            default: return <Shield className="w-4 h-4" />;
        }
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title flex items-center gap-2">
                        <Shield className="w-5 h-5" />
                        {isEditing ? 'Edit Role' : 'Create New Role'}
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
                    {/* Role Name */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Role Name *</span>
                        </label>
                        <input
                            type="text"
                            className={`input input-bordered ${errors.name ? 'input-error' : ''}`}
                            placeholder="Enter role name (e.g., Developer, Manager)"
                            value={formData.name}
                            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                        />
                        {errors.name && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.name}</span>
                            </label>
                        )}
                    </div>

                    {/* Description */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Description *</span>
                        </label>
                        <textarea
                            className={`textarea textarea-bordered h-20 ${errors.description ? 'textarea-error' : ''}`}
                            placeholder="Describe what this role is for and who should have it..."
                            value={formData.description}
                            onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                        />
                        {errors.description && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.description}</span>
                            </label>
                        )}
                    </div>

                    {/* Permissions */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Permissions *</span>
                            <span className="label-text-alt">{formData.permissions.length} selected</span>
                        </label>
                        
                        <div className="space-y-4 border border-base-300 rounded-lg p-4 max-h-96 overflow-y-auto">
                            {Object.entries(permissionsByCategory).map(([category, permissions]) => {
                                const categoryPermissionIds = permissions.map(p => p.id);
                                const selectedInCategory = categoryPermissionIds.filter(id => formData.permissions.includes(id));
                                const allSelected = selectedInCategory.length === categoryPermissionIds.length;
                                const someSelected = selectedInCategory.length > 0;
                                
                                return (
                                    <div key={category} className="space-y-2">
                                        <div className="flex items-center justify-between p-2 bg-base-200 rounded">
                                            <div className="flex items-center gap-2">
                                                {getCategoryIcon(category)}
                                                <span className="font-semibold">{category}</span>
                                                <span className="text-sm text-base-content/70">
                                                    ({selectedInCategory.length}/{categoryPermissionIds.length})
                                                </span>
                                            </div>
                                            <button
                                                type="button"
                                                className={`btn btn-xs ${allSelected ? 'btn-primary' : someSelected ? 'btn-outline btn-primary' : 'btn-ghost'}`}
                                                onClick={() => handleSelectAllInCategory(category)}
                                            >
                                                {allSelected ? 'Deselect All' : 'Select All'}
                                            </button>
                                        </div>
                                        
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 ml-4">
                                            {permissions.map(permission => (
                                                <label key={permission.id} className="label cursor-pointer justify-start gap-3 p-2 hover:bg-base-100 rounded">
                                                    <input
                                                        type="checkbox"
                                                        className="checkbox checkbox-sm"
                                                        checked={formData.permissions.includes(permission.id)}
                                                        onChange={() => handlePermissionToggle(permission.id)}
                                                    />
                                                    <div className="flex-1">
                                                        <div className="font-medium text-sm">{permission.name}</div>
                                                        <div className="text-xs text-base-content/60">{permission.description}</div>
                                                    </div>
                                                </label>
                                            ))}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        
                        {errors.permissions && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.permissions}</span>
                            </label>
                        )}
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
                            {isEditing ? 'Update Role' : 'Create Role'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}