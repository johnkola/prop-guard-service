'use client';

import { useState, useEffect } from 'react';
import { Shield, Search, RefreshCw, Filter } from 'lucide-react';
import RolesList from './RolesList';
import RoleForm from './RoleForm';
import Pagination from '../../components/Pagination';
import { ApiClient } from '../../lib/api';

interface Role {
    id: string;
    name: string;
    description: string;
    permissions: string[];
    isSystem: boolean;
    createdAt: string;
    createdBy: string;
}

type ViewMode = 'list' | 'create' | 'edit';

export default function RoleManager() {
    const [roles, setRoles] = useState<Role[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<ViewMode>('list');
    const [selectedRole, setSelectedRole] = useState<Role | null>(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [typeFilter, setTypeFilter] = useState<'all' | 'system' | 'custom'>('all');
    const [refreshing, setRefreshing] = useState(false);
    
    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(12); // Grid view shows fewer per page
    const [totalItems, setTotalItems] = useState(0);

    // Load roles from API with pagination
    const loadRoles = async (page = currentPage) => {
        try {
            setRefreshing(true);
            const queryParams = new URLSearchParams({
                limit: (itemsPerPage * 3).toString(), // Load more for client-side filtering
                offset: '0' // Always load from beginning for filtering
            });
            
            const response = await ApiClient.get<{roles: Role[], total: number} | Role[]>(`/v1/roles?${queryParams}`);
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            let allRoles: Role[] = [];
            let total = 0;
            
            // Handle both paginated and non-paginated responses
            if (Array.isArray(response.data)) {
                allRoles = response.data;
                total = allRoles.length;
            } else if (response.data && 'roles' in response.data) {
                allRoles = response.data.roles || [];
                total = response.data.total || allRoles.length;
            }
            
            // Store all roles for filtering
            setRoles(allRoles);
            setTotalItems(total);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load roles');
            // Set default roles if API fails
            const defaultRoles = [
                {
                    id: 'role_admin',
                    name: 'Administrator',
                    description: 'Full system access with all permissions',
                    permissions: ['secret:*', 'user:*', 'role:*', 'audit:*', 'system:*'],
                    isSystem: true,
                    createdAt: '2024-01-01T00:00:00Z',
                    createdBy: 'system',
                },
                {
                    id: 'role_user',
                    name: 'User',
                    description: 'Standard user with basic secret access',
                    permissions: ['secret:read', 'secret:list'],
                    isSystem: true,
                    createdAt: '2024-01-01T00:00:00Z',
                    createdBy: 'system',
                },
            ];
            setRoles(defaultRoles);
            setTotalItems(defaultRoles.length);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    // Create new role
    const createRole = async (roleData: {name: string; description: string; permissions: string[]}) => {
        try {
            setLoading(true);
            const response = await ApiClient.post<Role>('/v1/roles', roleData);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadRoles(); // Refresh the list
            setViewMode('list');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to create role');
        } finally {
            setLoading(false);
        }
    };

    // Update existing role
    const updateRole = async (roleData: {name: string; description: string; permissions: string[]}) => {
        if (!selectedRole) return;
        
        try {
            setLoading(true);
            const response = await ApiClient.put<Role>(`/v1/roles/${selectedRole.id}`, roleData);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadRoles(); // Refresh the list
            setViewMode('list');
            setSelectedRole(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to update role');
        } finally {
            setLoading(false);
        }
    };

    // Delete role
    const deleteRole = async (roleId: string) => {
        const role = roles.find(r => r.id === roleId);
        if (!role) return;
        
        if (role.isSystem) {
            setError('System roles cannot be deleted');
            return;
        }
        
        if (!confirm(`Are you sure you want to delete role "${role.name}"? This action cannot be undone and may affect users with this role.`)) {
            return;
        }

        try {
            setLoading(true);
            const response = await ApiClient.delete(`/v1/roles/${roleId}`);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadRoles(); // Refresh the list
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete role');
        } finally {
            setLoading(false);
        }
    };

    // Handle edit role
    const handleEditRole = (role: Role) => {
        if (role.isSystem) {
            setError('System roles cannot be modified');
            return;
        }
        setSelectedRole(role);
        setViewMode('edit');
    };

    // Handle form submission
    const handleFormSave = (roleData: {name: string; description: string; permissions: string[]}) => {
        if (viewMode === 'create') {
            createRole(roleData);
        } else if (viewMode === 'edit') {
            updateRole(roleData);
        }
    };

    // Handle cancel form
    const handleFormCancel = () => {
        setViewMode('list');
        setSelectedRole(null);
    };

    // Filter roles based on search term and type
    const filteredRoles = roles.filter(role => {
        const matchesSearch = 
            role.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            role.description.toLowerCase().includes(searchTerm.toLowerCase());
        
        const matchesType = 
            typeFilter === 'all' || 
            (typeFilter === 'system' && role.isSystem) ||
            (typeFilter === 'custom' && !role.isSystem);

        return matchesSearch && matchesType;
    });

    // Paginate the filtered results
    const startIndex = (currentPage - 1) * itemsPerPage;
    const paginatedRoles = filteredRoles.slice(startIndex, startIndex + itemsPerPage);

    // Handle page change
    const handlePageChange = (page: number) => {
        setCurrentPage(page);
    };

    // Handle items per page change
    const handleItemsPerPageChange = (newItemsPerPage: number) => {
        setItemsPerPage(newItemsPerPage);
        setCurrentPage(1);
    };

    // Calculate total pages based on filtered results
    const totalFilteredItems = filteredRoles.length;
    const totalPages = Math.ceil(totalFilteredItems / itemsPerPage);

    // Load data on component mount
    useEffect(() => {
        loadRoles();
    }, []);

    // Reset to page 1 when filter changes
    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm, typeFilter]);

    if (loading && roles.length === 0) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="loading loading-spinner loading-lg"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Shield className="w-6 h-6" />
                    <h1 className="text-2xl font-bold">Role Management</h1>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        className={`btn btn-ghost btn-sm ${refreshing ? 'loading' : ''}`}
                        onClick={loadRoles}
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
                                            placeholder="Search roles by name or description..."
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
                                            value={typeFilter}
                                            onChange={(e) => setTypeFilter(e.target.value as 'all' | 'system' | 'custom')}
                                        >
                                            <option value="all">All Roles</option>
                                            <option value="system">System Roles</option>
                                            <option value="custom">Custom Roles</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div className="text-sm text-base-content/70">
                                    {filteredRoles.length} of {roles.length} roles
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Roles List */}
                    <RolesList
                        roles={paginatedRoles}
                        onAddRole={() => setViewMode('create')}
                        onEditRole={handleEditRole}
                        onDeleteRole={deleteRole}
                    />
                    
                    {/* Pagination */}
                    <div className="card bg-base-100 shadow-sm">
                        <div className="card-body py-2">
                            <Pagination
                                currentPage={currentPage}
                                totalPages={totalPages}
                                totalItems={totalFilteredItems}
                                itemsPerPage={itemsPerPage}
                                onPageChange={handlePageChange}
                                onItemsPerPageChange={handleItemsPerPageChange}
                                showItemsPerPage={true}
                                itemsPerPageOptions={[6, 12, 24, 48]}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* View Mode: Create */}
            {viewMode === 'create' && (
                <RoleForm
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}

            {/* View Mode: Edit */}
            {viewMode === 'edit' && selectedRole && (
                <RoleForm
                    initialData={selectedRole}
                    isEditing={true}
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}
        </div>
    );
}