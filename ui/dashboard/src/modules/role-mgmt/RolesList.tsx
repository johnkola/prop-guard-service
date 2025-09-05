'use client';

import { Shield, Edit, Trash2, Plus, Users, Key, Calendar } from 'lucide-react';

interface Role {
    id: string;
    name: string;
    description: string;
    permissions: string[];
    isSystem: boolean;
    createdAt: string;
    createdBy: string;
}

interface RolesListProps {
    roles?: Role[];
    onAddRole?: () => void;
    onEditRole?: (role: Role) => void;
    onDeleteRole?: (roleId: string) => void;
}

export default function RolesList({ 
    roles = [], 
    onAddRole, 
    onEditRole, 
    onDeleteRole 
}: RolesListProps) {

    const getPermissionCategory = (permission: string) => {
        if (permission.includes('secret')) return 'Secrets';
        if (permission.includes('user')) return 'Users';
        if (permission.includes('role')) return 'Roles';
        if (permission.includes('audit')) return 'Audit';
        if (permission.includes('system')) return 'System';
        return 'Other';
    };

    const groupPermissionsByCategory = (permissions: string[]) => {
        const grouped = permissions.reduce((acc, perm) => {
            const category = getPermissionCategory(perm);
            acc[category] = (acc[category] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);
        
        return Object.entries(grouped).map(([category, count]) => ({ category, count }));
    };

    const getRoleBadgeColor = (role: Role) => {
        if (role.isSystem) return 'badge-warning';
        if (role.name.toLowerCase().includes('admin')) return 'badge-error';
        return 'badge-primary';
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title flex items-center gap-2">
                        <Shield className="w-5 h-5" />
                        Role Management
                    </h2>
                    {onAddRole && (
                        <button 
                            className="btn btn-primary btn-sm"
                            onClick={onAddRole}
                        >
                            <Plus className="w-4 h-4" />
                            Add Role
                        </button>
                    )}
                </div>

                {roles.length === 0 ? (
                    <div className="text-center py-12 text-base-content/60">
                        <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>No roles found</p>
                        <p className="text-sm">Create your first custom role to get started</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {/* Summary Stats */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">Total Roles</div>
                                <div className="stat-value text-primary">{roles.length}</div>
                            </div>
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">System Roles</div>
                                <div className="stat-value text-warning">{roles.filter(r => r.isSystem).length}</div>
                            </div>
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">Custom Roles</div>
                                <div className="stat-value text-success">{roles.filter(r => !r.isSystem).length}</div>
                            </div>
                        </div>

                        {/* Roles Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {roles.map((role) => {
                                const permissionCategories = groupPermissionsByCategory(role.permissions);
                                
                                return (
                                    <div key={role.id} className="card bg-base-200 shadow-sm hover:shadow-md transition-shadow">
                                        <div className="card-body p-4">
                                            <div className="flex items-start justify-between mb-3">
                                                <div className="flex-1">
                                                    <h3 className="font-semibold flex items-center gap-2 mb-1">
                                                        {role.name}
                                                        <span className={`badge badge-sm ${getRoleBadgeColor(role)}`}>
                                                            {role.isSystem ? 'System' : 'Custom'}
                                                        </span>
                                                    </h3>
                                                    <p className="text-sm text-base-content/70 line-clamp-2">
                                                        {role.description}
                                                    </p>
                                                </div>
                                            </div>

                                            {/* Permissions Summary */}
                                            <div className="space-y-2 mb-4">
                                                <div className="flex items-center gap-2 text-sm font-medium">
                                                    <Key className="w-4 h-4" />
                                                    <span>{role.permissions.length} permissions</span>
                                                </div>
                                                
                                                {permissionCategories.length > 0 && (
                                                    <div className="flex flex-wrap gap-1">
                                                        {permissionCategories.map(({ category, count }) => (
                                                            <span 
                                                                key={category} 
                                                                className="badge badge-xs badge-outline"
                                                            >
                                                                {category} ({count})
                                                            </span>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>

                                            {/* Metadata */}
                                            <div className="flex items-center justify-between text-xs text-base-content/60 mb-3">
                                                <div className="flex items-center gap-1">
                                                    <Calendar className="w-3 h-3" />
                                                    <span>{new Date(role.createdAt).toLocaleDateString()}</span>
                                                </div>
                                                <span>by {role.createdBy}</span>
                                            </div>

                                            {/* Actions */}
                                            <div className="card-actions justify-end pt-2 border-t border-base-300">
                                                {onEditRole && (
                                                    <button
                                                        className="btn btn-ghost btn-sm"
                                                        onClick={() => onEditRole(role)}
                                                        title="Edit role"
                                                    >
                                                        <Edit className="w-4 h-4" />
                                                    </button>
                                                )}
                                                {onDeleteRole && !role.isSystem && (
                                                    <button
                                                        className="btn btn-ghost btn-sm text-error hover:bg-error hover:text-error-content"
                                                        onClick={() => onDeleteRole(role.id)}
                                                        title="Delete role"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                )}
                                                {role.isSystem && (
                                                    <div className="tooltip" data-tip="System roles cannot be deleted">
                                                        <button className="btn btn-ghost btn-sm" disabled>
                                                            <Trash2 className="w-4 h-4 opacity-30" />
                                                        </button>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}