'use client';

import { useState, useEffect } from 'react';
import { Key, Search, Filter, RefreshCw } from 'lucide-react';
import SecretsList from './SecretsList';
import SecretForm from './SecretForm';
import Pagination from '../../components/Pagination';
import { ApiClient } from '../../lib/api';

interface Secret {
    id: string;
    path: string;
    data: Record<string, any>;
    createdAt: string;
    updatedAt: string;
    createdBy: string;
    version: number;
    ttlSeconds?: number;
}

type ViewMode = 'list' | 'create' | 'edit';

export default function SecretManager() {
    const [secrets, setSecrets] = useState<Secret[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<ViewMode>('list');
    const [selectedSecret, setSelectedSecret] = useState<Secret | null>(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [refreshing, setRefreshing] = useState(false);
    
    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(20);
    const [totalItems, setTotalItems] = useState(0);

    // Load secrets from API with pagination
    const loadSecrets = async (page = currentPage) => {
        try {
            setRefreshing(true);
            const offset = (page - 1) * itemsPerPage;
            const queryParams = new URLSearchParams({
                limit: itemsPerPage.toString(),
                offset: offset.toString()
            });
            
            const response = await ApiClient.get<{secrets: Secret[], total: number}>(`/v1/secrets?${queryParams}`);
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            // If API doesn't return paginated data, handle it gracefully
            if (Array.isArray(response.data)) {
                // Legacy API response - simulate pagination
                const allSecrets = response.data as any as Secret[];
                const paginatedSecrets = allSecrets.slice(offset, offset + itemsPerPage);
                setSecrets(paginatedSecrets);
                setTotalItems(allSecrets.length);
            } else {
                // Paginated API response
                setSecrets(response.data?.secrets || []);
                setTotalItems(response.data?.total || 0);
            }
            
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load secrets');
            setSecrets([]);
            setTotalItems(0);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    // Create new secret
    const createSecret = async (secretData: { path: string; data: Record<string, any>; ttlSeconds?: number }) => {
        try {
            setLoading(true);
            const response = await ApiClient.post(`/v1/secrets${secretData.path}`, {
                data: secretData.data,
                ttlSeconds: secretData.ttlSeconds,
            });

            if (response.error) {
                throw new Error(response.error);
            }

            await loadSecrets(); // Refresh the list
            setViewMode('list');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to create secret');
        } finally {
            setLoading(false);
        }
    };

    // Update existing secret
    const updateSecret = async (secretData: { path: string; data: Record<string, any>; ttlSeconds?: number }) => {
        if (!selectedSecret) return;
        
        try {
            setLoading(true);
            const response = await ApiClient.put(`/v1/secrets${selectedSecret.path}`, {
                data: secretData.data,
                ttlSeconds: secretData.ttlSeconds,
            });

            if (response.error) {
                throw new Error(response.error);
            }

            await loadSecrets(); // Refresh the list
            setViewMode('list');
            setSelectedSecret(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to update secret');
        } finally {
            setLoading(false);
        }
    };

    // Delete secret
    const deleteSecret = async (secretPath: string) => {
        if (!confirm('Are you sure you want to delete this secret? This action cannot be undone.')) {
            return;
        }

        try {
            setLoading(true);
            const response = await ApiClient.delete(`/v1/secrets${secretPath}`);

            if (response.error) {
                throw new Error(response.error);
            }

            await loadSecrets(); // Refresh the list
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete secret');
        } finally {
            setLoading(false);
        }
    };

    // Handle edit secret
    const handleEditSecret = (secret: Secret) => {
        setSelectedSecret(secret);
        setViewMode('edit');
    };

    // Handle form submission
    const handleFormSave = (secretData: { path: string; data: Record<string, any>; ttlSeconds?: number }) => {
        if (viewMode === 'create') {
            createSecret(secretData);
        } else if (viewMode === 'edit') {
            updateSecret(secretData);
        }
    };

    // Handle cancel form
    const handleFormCancel = () => {
        setViewMode('list');
        setSelectedSecret(null);
    };

    // Filter secrets based on search term (client-side filtering for displayed page)
    const filteredSecrets = secrets.filter(secret =>
        secret.path.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // Handle page change
    const handlePageChange = (page: number) => {
        setCurrentPage(page);
        loadSecrets(page);
    };

    // Handle items per page change
    const handleItemsPerPageChange = (newItemsPerPage: number) => {
        setItemsPerPage(newItemsPerPage);
        setCurrentPage(1); // Reset to first page
    };

    // Calculate total pages
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    // Load secrets on component mount and when pagination changes
    useEffect(() => {
        loadSecrets();
    }, [currentPage, itemsPerPage]);

    if (loading && secrets.length === 0) {
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
                    <Key className="w-6 h-6" />
                    <h1 className="text-2xl font-bold">Secret Management</h1>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        className={`btn btn-ghost btn-sm ${refreshing ? 'loading' : ''}`}
                        onClick={loadSecrets}
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
                            <div className="flex items-center gap-4">
                                <div className="form-control flex-1">
                                    <div className="input-group">
                                        <span>
                                            <Search className="w-4 h-4" />
                                        </span>
                                        <input
                                            type="text"
                                            className="input input-bordered flex-1"
                                            placeholder="Search secrets by path..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                        />
                                    </div>
                                </div>
                                <div className="text-sm text-base-content/70">
                                    {filteredSecrets.length} of {secrets.length} secrets
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Secrets List */}
                    <SecretsList
                        secrets={filteredSecrets}
                        onAddSecret={() => setViewMode('create')}
                        onEditSecret={handleEditSecret}
                        onDeleteSecret={(secretId) => {
                            const secret = secrets.find(s => s.id === secretId);
                            if (secret) deleteSecret(secret.path);
                        }}
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
                <SecretForm
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}

            {/* View Mode: Edit */}
            {viewMode === 'edit' && selectedSecret && (
                <SecretForm
                    initialData={{
                        path: selectedSecret.path,
                        data: selectedSecret.data,
                        ttlSeconds: selectedSecret.ttlSeconds,
                    }}
                    isEditing={true}
                    onSave={handleFormSave}
                    onCancel={handleFormCancel}
                />
            )}
        </div>
    );
}