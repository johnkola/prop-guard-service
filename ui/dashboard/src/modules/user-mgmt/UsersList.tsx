'use client';

import { useState } from 'react';
import { Users, Edit, Trash2, Plus, Shield, Mail, Calendar, CheckCircle, XCircle } from 'lucide-react';

interface User {
    id: string;
    username: string;
    email: string;
    roles: string[];
    enabled: boolean;
    createdAt: string;
    updatedAt: string;
    lastLogin?: string;
}

interface UsersListProps {
    users?: User[];
    onAddUser?: () => void;
    onEditUser?: (user: User) => void;
    onDeleteUser?: (userId: string) => void;
}

export default function UsersList({ 
    users = [], 
    onAddUser, 
    onEditUser, 
    onDeleteUser 
}: UsersListProps) {
    const [sortBy, setSortBy] = useState<'username' | 'email' | 'createdAt'>('username');
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

    const sortedUsers = [...users].sort((a, b) => {
        let aValue = a[sortBy];
        let bValue = b[sortBy];

        if (sortBy === 'createdAt') {
            aValue = new Date(aValue).getTime();
            bValue = new Date(bValue).getTime();
        }

        if (sortOrder === 'asc') {
            return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
        } else {
            return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
        }
    });

    const handleSort = (field: typeof sortBy) => {
        if (sortBy === field) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
        } else {
            setSortBy(field);
            setSortOrder('asc');
        }
    };

    const getRoleColor = (role: string) => {
        switch (role.toLowerCase()) {
            case 'role_admin':
                return 'badge-error';
            case 'role_user':
                return 'badge-primary';
            case 'role_viewer':
                return 'badge-info';
            default:
                return 'badge-neutral';
        }
    };

    const formatRoleName = (role: string) => {
        return role.replace('role_', '').replace('_', ' ').toUpperCase();
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title flex items-center gap-2">
                        <Users className="w-5 h-5" />
                        User Management
                    </h2>
                    {onAddUser && (
                        <button 
                            className="btn btn-primary btn-sm"
                            onClick={onAddUser}
                        >
                            <Plus className="w-4 h-4" />
                            Add User
                        </button>
                    )}
                </div>

                {users.length === 0 ? (
                    <div className="text-center py-12 text-base-content/60">
                        <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>No users found</p>
                        <p className="text-sm">Create your first user to get started</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {/* Summary Stats */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">Total Users</div>
                                <div className="stat-value text-primary">{users.length}</div>
                            </div>
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">Active Users</div>
                                <div className="stat-value text-success">{users.filter(u => u.enabled).length}</div>
                            </div>
                            <div className="stat bg-base-200 rounded-lg">
                                <div className="stat-title">Disabled Users</div>
                                <div className="stat-value text-error">{users.filter(u => !u.enabled).length}</div>
                            </div>
                        </div>

                        {/* Desktop Table View */}
                        <div className="hidden lg:block overflow-x-auto">
                            <table className="table table-zebra">
                                <thead>
                                    <tr>
                                        <th>
                                            <button 
                                                className="btn btn-ghost btn-xs"
                                                onClick={() => handleSort('username')}
                                            >
                                                Username {sortBy === 'username' && (sortOrder === 'asc' ? '↑' : '↓')}
                                            </button>
                                        </th>
                                        <th>
                                            <button 
                                                className="btn btn-ghost btn-xs"
                                                onClick={() => handleSort('email')}
                                            >
                                                Email {sortBy === 'email' && (sortOrder === 'asc' ? '↑' : '↓')}
                                            </button>
                                        </th>
                                        <th>Roles</th>
                                        <th>Status</th>
                                        <th>
                                            <button 
                                                className="btn btn-ghost btn-xs"
                                                onClick={() => handleSort('createdAt')}
                                            >
                                                Created {sortBy === 'createdAt' && (sortOrder === 'asc' ? '↑' : '↓')}
                                            </button>
                                        </th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {sortedUsers.map((user) => (
                                        <tr key={user.id}>
                                            <td>
                                                <div className="font-semibold">{user.username}</div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-2">
                                                    <Mail className="w-4 h-4 text-base-content/50" />
                                                    {user.email}
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex flex-wrap gap-1">
                                                    {user.roles.map(role => (
                                                        <span 
                                                            key={role} 
                                                            className={`badge badge-sm ${getRoleColor(role)}`}
                                                        >
                                                            {formatRoleName(role)}
                                                        </span>
                                                    ))}
                                                </div>
                                            </td>
                                            <td>
                                                {user.enabled ? (
                                                    <div className="flex items-center gap-1 text-success">
                                                        <CheckCircle className="w-4 h-4" />
                                                        <span>Active</span>
                                                    </div>
                                                ) : (
                                                    <div className="flex items-center gap-1 text-error">
                                                        <XCircle className="w-4 h-4" />
                                                        <span>Disabled</span>
                                                    </div>
                                                )}
                                            </td>
                                            <td>
                                                <div className="text-sm text-base-content/70">
                                                    {new Date(user.createdAt).toLocaleDateString()}
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-2">
                                                    {onEditUser && (
                                                        <button
                                                            className="btn btn-ghost btn-sm"
                                                            onClick={() => onEditUser(user)}
                                                            title="Edit user"
                                                        >
                                                            <Edit className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                    {onDeleteUser && (
                                                        <button
                                                            className="btn btn-ghost btn-sm text-error hover:bg-error hover:text-error-content"
                                                            onClick={() => onDeleteUser(user.id)}
                                                            title="Delete user"
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Mobile Card View */}
                        <div className="lg:hidden space-y-4">
                            {sortedUsers.map((user) => (
                                <div key={user.id} className="card bg-base-200 shadow-sm">
                                    <div className="card-body p-4">
                                        <div className="flex items-center justify-between mb-2">
                                            <h3 className="font-semibold">{user.username}</h3>
                                            {user.enabled ? (
                                                <CheckCircle className="w-5 h-5 text-success" />
                                            ) : (
                                                <XCircle className="w-5 h-5 text-error" />
                                            )}
                                        </div>
                                        
                                        <div className="flex items-center gap-2 text-sm text-base-content/70 mb-2">
                                            <Mail className="w-4 h-4" />
                                            {user.email}
                                        </div>
                                        
                                        <div className="flex flex-wrap gap-1 mb-3">
                                            {user.roles.map(role => (
                                                <span 
                                                    key={role} 
                                                    className={`badge badge-sm ${getRoleColor(role)}`}
                                                >
                                                    {formatRoleName(role)}
                                                </span>
                                            ))}
                                        </div>
                                        
                                        <div className="flex items-center justify-between text-xs text-base-content/60">
                                            <div className="flex items-center gap-1">
                                                <Calendar className="w-3 h-3" />
                                                Created: {new Date(user.createdAt).toLocaleDateString()}
                                            </div>
                                            <div className="flex items-center gap-2">
                                                {onEditUser && (
                                                    <button
                                                        className="btn btn-ghost btn-sm"
                                                        onClick={() => onEditUser(user)}
                                                    >
                                                        <Edit className="w-4 h-4" />
                                                    </button>
                                                )}
                                                {onDeleteUser && (
                                                    <button
                                                        className="btn btn-ghost btn-sm text-error"
                                                        onClick={() => onDeleteUser(user.id)}
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}