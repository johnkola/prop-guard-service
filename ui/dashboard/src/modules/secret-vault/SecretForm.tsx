'use client';

import { useState } from 'react';
import { Save, X, Plus, Trash2 } from 'lucide-react';

interface SecretFormData {
    path: string;
    data: Record<string, any>;
    ttlSeconds?: number;
}

interface SecretFormProps {
    initialData?: Partial<SecretFormData>;
    isEditing?: boolean;
    onSave?: (data: SecretFormData) => void;
    onCancel?: () => void;
}

export default function SecretForm({ 
    initialData, 
    isEditing = false, 
    onSave, 
    onCancel 
}: SecretFormProps) {
    const [formData, setFormData] = useState<SecretFormData>({
        path: initialData?.path || '',
        data: initialData?.data || {},
        ttlSeconds: initialData?.ttlSeconds,
    });

    const [keyValuePairs, setKeyValuePairs] = useState(() => {
        const pairs = Object.entries(formData.data || {});
        return pairs.length > 0 ? pairs : [['', '']];
    });

    const [errors, setErrors] = useState<Record<string, string>>({});

    const validateForm = (): boolean => {
        const newErrors: Record<string, string> = {};

        if (!formData.path.trim()) {
            newErrors.path = 'Path is required';
        } else if (!formData.path.startsWith('/')) {
            newErrors.path = 'Path must start with /';
        }

        const validPairs = keyValuePairs.filter(([k, v]) => k.trim() && v.trim());
        if (validPairs.length === 0) {
            newErrors.data = 'At least one key-value pair is required';
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!validateForm()) return;

        const validPairs = keyValuePairs.filter(([k, v]) => k.trim() && v.trim());
        const dataObject = Object.fromEntries(validPairs);

        const submitData: SecretFormData = {
            path: formData.path,
            data: dataObject,
        };

        if (formData.ttlSeconds && formData.ttlSeconds > 0) {
            submitData.ttlSeconds = formData.ttlSeconds;
        }

        onSave?.(submitData);
    };

    const addKeyValuePair = () => {
        setKeyValuePairs([...keyValuePairs, ['', '']]);
    };

    const removeKeyValuePair = (index: number) => {
        setKeyValuePairs(keyValuePairs.filter((_, i) => i !== index));
    };

    const updateKeyValuePair = (index: number, key: string, value: string) => {
        const newPairs = [...keyValuePairs];
        newPairs[index] = [key, value];
        setKeyValuePairs(newPairs);
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="card-title">
                        {isEditing ? 'Edit Secret' : 'Create New Secret'}
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
                    {/* Path Input */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Secret Path *</span>
                        </label>
                        <input
                            type="text"
                            className={`input input-bordered ${errors.path ? 'input-error' : ''}`}
                            placeholder="/app/database/password"
                            value={formData.path}
                            onChange={(e) => setFormData(prev => ({ ...prev, path: e.target.value }))}
                        />
                        {errors.path && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.path}</span>
                            </label>
                        )}
                    </div>

                    {/* TTL Input */}
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">TTL (seconds)</span>
                            <span className="label-text-alt">Optional expiration time</span>
                        </label>
                        <input
                            type="number"
                            className="input input-bordered"
                            placeholder="3600"
                            min="0"
                            value={formData.ttlSeconds || ''}
                            onChange={(e) => setFormData(prev => ({ 
                                ...prev, 
                                ttlSeconds: e.target.value ? parseInt(e.target.value) : undefined 
                            }))}
                        />
                    </div>

                    {/* Key-Value Pairs */}
                    <div className="form-control">
                        <div className="flex items-center justify-between mb-3">
                            <label className="label-text">Secret Data *</label>
                            <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                onClick={addKeyValuePair}
                            >
                                <Plus className="w-4 h-4" />
                                Add Field
                            </button>
                        </div>
                        
                        <div className="space-y-3">
                            {keyValuePairs.map(([key, value], index) => (
                                <div key={index} className="flex gap-2 items-center">
                                    <input
                                        type="text"
                                        className="input input-bordered input-sm flex-1"
                                        placeholder="Key"
                                        value={key}
                                        onChange={(e) => updateKeyValuePair(index, e.target.value, value)}
                                    />
                                    <span className="text-base-content/50">:</span>
                                    <input
                                        type="text"
                                        className="input input-bordered input-sm flex-1"
                                        placeholder="Value"
                                        value={value}
                                        onChange={(e) => updateKeyValuePair(index, key, e.target.value)}
                                    />
                                    {keyValuePairs.length > 1 && (
                                        <button
                                            type="button"
                                            className="btn btn-ghost btn-sm text-error hover:bg-error hover:text-error-content"
                                            onClick={() => removeKeyValuePair(index)}
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    )}
                                </div>
                            ))}
                        </div>
                        
                        {errors.data && (
                            <label className="label">
                                <span className="label-text-alt text-error">{errors.data}</span>
                            </label>
                        )}
                    </div>

                    {/* Actions */}
                    <div className="card-actions justify-end pt-4">
                        {onCancel && (
                            <button type="button" className="btn btn-ghost" onClick={onCancel}>
                                Cancel
                            </button>
                        )}
                        <button type="submit" className="btn btn-primary">
                            <Save className="w-4 h-4" />
                            {isEditing ? 'Update Secret' : 'Create Secret'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}