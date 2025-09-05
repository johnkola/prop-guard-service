'use client';

import { useState } from 'react';
import { Key, Eye, EyeOff, Copy, Edit, Trash2, Plus } from 'lucide-react';

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

interface SecretsListProps {
    secrets?: Secret[];
    onAddSecret?: () => void;
    onEditSecret?: (secret: Secret) => void;
    onDeleteSecret?: (secretId: string) => void;
}

export default function SecretsList({ 
    secrets = [], 
    onAddSecret, 
    onEditSecret, 
    onDeleteSecret 
}: SecretsListProps) {
    const [visibleSecrets, setVisibleSecrets] = useState<Set<string>>(new Set());

    const toggleSecretVisibility = (secretId: string) => {
        setVisibleSecrets(prev => {
            const newSet = new Set(prev);
            if (newSet.has(secretId)) {
                newSet.delete(secretId);
            } else {
                newSet.add(secretId);
            }
            return newSet;
        });
    };

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text);
            // You could add a toast notification here
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title flex items-center gap-2">
                        <Key className="w-5 h-5" />
                        Secrets & Properties
                    </h2>
                    {onAddSecret && (
                        <button 
                            className="btn btn-primary btn-sm"
                            onClick={onAddSecret}
                        >
                            <Plus className="w-4 h-4" />
                            Add Secret
                        </button>
                    )}
                </div>

                {secrets.length === 0 ? (
                    <div className="text-center py-12 text-base-content/60">
                        <Key className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>No secrets found</p>
                        <p className="text-sm">Add your first secret to get started</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {secrets.map((secret) => (
                            <div key={secret.id} className="border border-base-200 rounded-lg p-4">
                                <div className="flex items-center justify-between">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2 mb-2">
                                            <h3 className="font-semibold">{secret.path}</h3>
                                            <button
                                                className="btn btn-ghost btn-xs"
                                                onClick={() => copyToClipboard(secret.path)}
                                                title="Copy path"
                                            >
                                                <Copy className="w-3 h-3" />
                                            </button>
                                        </div>
                                        <div className="text-sm text-base-content/70 mb-2">
                                            <span className="badge badge-primary badge-sm mr-2">v{secret.version}</span>
                                            {Object.keys(secret.data).length} field{Object.keys(secret.data).length !== 1 ? 's' : ''}
                                            {secret.ttlSeconds && (
                                                <span className="badge badge-warning badge-sm ml-2">
                                                    TTL: {secret.ttlSeconds}s
                                                </span>
                                            )}
                                        </div>
                                        <div className="flex items-center gap-4 text-xs text-base-content/60">
                                            <span>Created: {new Date(secret.createdAt).toLocaleDateString()}</span>
                                            <span>Updated: {new Date(secret.updatedAt).toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <button
                                            className="btn btn-ghost btn-sm"
                                            onClick={() => toggleSecretVisibility(secret.id)}
                                            title={visibleSecrets.has(secret.id) ? "Hide secret" : "Show secret"}
                                        >
                                            {visibleSecrets.has(secret.id) ? (
                                                <EyeOff className="w-4 h-4" />
                                            ) : (
                                                <Eye className="w-4 h-4" />
                                            )}
                                        </button>
                                        {onEditSecret && (
                                            <button
                                                className="btn btn-ghost btn-sm"
                                                onClick={() => onEditSecret(secret)}
                                                title="Edit secret"
                                            >
                                                <Edit className="w-4 h-4" />
                                            </button>
                                        )}
                                        {onDeleteSecret && (
                                            <button
                                                className="btn btn-ghost btn-sm text-error hover:bg-error hover:text-error-content"
                                                onClick={() => onDeleteSecret(secret.id)}
                                                title="Delete secret"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                </div>
                                {visibleSecrets.has(secret.id) && (
                                    <div className="mt-4 p-3 bg-base-200 rounded-md">
                                        <div className="space-y-2">
                                            {Object.entries(secret.data).map(([key, value]) => (
                                                <div key={key} className="flex items-center gap-2">
                                                    <span className="font-semibold text-sm min-w-0 flex-shrink-0">
                                                        {key}:
                                                    </span>
                                                    <div className="font-mono text-sm flex-1 min-w-0">
                                                        <span className="blur-sm hover:blur-none transition-all cursor-pointer select-all">
                                                            {typeof value === 'string' ? value : JSON.stringify(value)}
                                                        </span>
                                                    </div>
                                                    <button
                                                        className="btn btn-ghost btn-xs"
                                                        onClick={() => copyToClipboard(typeof value === 'string' ? value : JSON.stringify(value))}
                                                        title={`Copy ${key}`}
                                                    >
                                                        <Copy className="w-3 h-3" />
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}