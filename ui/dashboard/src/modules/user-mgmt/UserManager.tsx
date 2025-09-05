'use client';

import { useState, useEffect } from 'react';
import { Users, Search, RefreshCw, Filter } from 'lucide-react';
import UsersList from './UsersList';
import UserForm from './UserForm';
import Pagination from '../../components/Pagination';
import { ApiClient } from '../../lib/api';

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

interface Role {
    id: string;
    name: string;
    description: string;
    permissions: string[];
}

type ViewMode = 'list' | 'create' | 'edit';

export default function UserManager() {
    const [users, setUsers] = useState<User[]>([]);
    const [roles, setRoles] = useState<Role[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<ViewMode>('list');
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled'>('all');
    const [refreshing, setRefreshing] = useState(false);
    
    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(20);
    const [totalItems, setTotalItems] = useState(0);

    // Load users from API with pagination
    const loadUsers = async (page = currentPage) => {
        try {
            setRefreshing(true);
            const queryParams = new URLSearchParams({
                page: page.toString(),
                pageSize: itemsPerPage.toString()
            });
            
            const response = await ApiClient.get<{users: User[], total: number, page: number, pageSize: number, totalPages: number}>(`/v1/users?${queryParams}`);
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            if (response.data) {
                setUsers(response.data.users || []);
                setTotalItems(response.data.total || 0);
            } else {
                setUsers([]);
                setTotalItems(0);
            }
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load users');
            setUsers([]);
            setTotalItems(0);
        } finally {
            setRefreshing(false);
        }
    };

    // Load roles from API
    const loadRoles = async () => {
        try {
            const response = await ApiClient.get<Role[]>('/v1/roles');
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            setRoles(response.data || []);
        } catch (err) {
            console.error('Failed to load roles:', err);
            // Set default roles if API fails
            setRoles([
                { id: 'role_user', name: 'User', description: 'Standard user role', permissions: [] },
                { id: 'role_admin', name: 'Admin', description: 'Administrator role', permissions: [] },
            ]);
        } finally {
            setLoading(false);
        }
    };

    // Create new user
    const createUser = async (userData: {username: string; email: string; password: string; roles: string[]; enabled: boolean}) => {
        try {
            setLoading(true);
            const response = await ApiClient.post<User>('/v1/users', userData);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadUsers(); // Refresh the list
            setViewMode('list');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to create user');
        } finally {
            setLoading(false);
        }
    };

    // Update existing user
    const updateUser = async (userData: {username: string; email: string; password?: string; roles: string[]; enabled: boolean}) => {
        if (!selectedUser) return;
        
        try {
            setLoading(true);
            const response = await ApiClient.put<User>(`/v1/users/${selectedUser.id}`, userData);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadUsers(); // Refresh the list
            setViewMode('list');
            setSelectedUser(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to update user');
        } finally {
            setLoading(false);
        }
    };

    // Delete user
    const deleteUser = async (userId: string) => {
        const user = users.find(u => u.id === userId);
        if (!user || !confirm(`Are you sure you want to delete user "${user.username}"? This action cannot be undone.`)) {
            return;
        }

        try {
            setLoading(true);
            const response = await ApiClient.delete(`/v1/users/${userId}`);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadUsers(); // Refresh the list
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete user');
        } finally {
            setLoading(false);
        }
    };

    // Handle edit user
    const handleEditUser = (user: User) => {
        setSelectedUser(user);
        setViewMode('edit');
    };

    // Handle form submission
    const handleFormSave = (userData: {username: string; email: string; password?: string; roles: string[]; enabled: boolean}) => {
        if (viewMode === 'create') {
            createUser({ ...userData, password: userData.password || '' });
        } else if (viewMode === 'edit') {
            updateUser(userData);
        }
    };

    // Handle cancel form
    const handleFormCancel = () => {
        setViewMode('list');
        setSelectedUser(null);
    };

    // Filter users based on search term and status
    const filteredUsers = users.filter(user => {
        const matchesSearch = 
            user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
            user.email.toLowerCase().includes(searchTerm.toLowerCase());
        
        const matchesStatus = 
            statusFilter === 'all' || 
            (statusFilter === 'active' && user.enabled) ||
            (statusFilter === 'disabled' && !user.enabled);

        return matchesSearch && matchesStatus;
    });

    // Handle page change
    const handlePageChange = (page: number) => {
        setCurrentPage(page);
        loadUsers(page);
    };

    // Handle items per page change
    const handleItemsPerPageChange = (newItemsPerPage: number) => {
        setItemsPerPage(newItemsPerPage);
        setCurrentPage(1);
    };

    // Calculate total pages
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    // Load data on component mount and when pagination changes
    useEffect(() => {
        loadUsers();
    }, [currentPage, itemsPerPage]);

    // Load roles once on mount
    useEffect(() => {
        loadRoles();
    }, []);

    if (loading && users.length === 0) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="loading loading-spinner loading-lg"></div>
            </div>
        );
    }

    const availableRoles = roles.map(role => role.id);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Users className="w-6 h-6" />
                    <h1 className="text-2xl font-bold">User Management</h1>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        className={`btn btn-ghost btn-sm ${refreshing ? 'loading' : ''}`}
                        onClick={() => Promise.all([loadUsers(), loadRoles()])}
                        disabled={refreshing}
                    >
                        {!refreshing && <RefreshCw className="w-4 h-4" />}
                        Refresh
                    </button>
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div className="alert alert-error">
                    <span>{error}</span>
                    <button 
                        className="btn btn-ghost btn-sm"
                        onClick={() => setError(null)}
                    >
                        Dismiss
                    </button>
                </div>
            )}

            {/* View Mode: List */}
            {viewMode === 'list' && (
                <div className="space-y-4">
                    {/* Search and Filters */}
                    <div className="card bg-base-100 shadow-sm">
                        <div className="card-body py-4">
                            <div className="flex flex-col md:flex-row items-center gap-4">
                                <div className="form-control flex-1">
                                    <div className="input-group">
                                        <span>
                                            <Search className="w-4 h-4" />
                                        </span>
                                        <input
                                            type="text"
                                            className="input input-bordered flex-1"
                                            placeholder="Search users by name or email..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                        />
                                    </div>
                                </div>
                                
                                <div className="form-control">
                                    <div className="input-group">
                                        <span>
                                            <Filter className="w-4 h-4" />
                                        </span>
                                        <select 
                                            className="select select-bordered"
                                            value={statusFilter}
                                            onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'disabled')}
                                        >
                                            <option value="all">All Users</option>
                                            <option value="active">Active Only</option>
                                            <option value="disabled">Disabled Only</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div className="text-sm text-base-content/70">
                                    {filteredUsers.length} of {users.length} users
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Users List */}
                    <UsersList
                        users={filteredUsers}
                        onAddUser={() => setViewMode('create')}
                        onEditUser={handleEditUser}
                        onDeleteUser={deleteUser}
                    />
                    
                    {/* Pagination */}
                    <div className="card bg-base-100 shadow-sm">
                        <div className="card-body py-2">
                            <Pagination
                                currentPage={currentPage}
                                totalPages={totalPages}
                                totalItems={totalItems}
                                itemsPerPage={itemsPerPage}
                                onPageChange={handlePageChange}
                                onItemsPerPageChange={handleItemsPerPageChange}
                                showItemsPerPage={true}
                                itemsPerPageOptions={[10, 20, 50, 100]}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* View Mode: Create */}
            {viewMode === 'create' && (
                <UserForm
                    availableRoles={availableRoles}
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}

            {/* View Mode: Edit */}
            {viewMode === 'edit' && selectedUser && (
                <UserForm
                    initialData={selectedUser}
                    availableRoles={availableRoles}
                    isEditing={true}
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}
        </div>
    );
}