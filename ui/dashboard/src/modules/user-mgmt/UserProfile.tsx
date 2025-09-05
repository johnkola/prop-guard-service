'use client';

import { useState } from 'react';
import { User, Edit, Save, X } from 'lucide-react';

interface UserProfileProps {
    username: string;
    email?: string;
    role: string;
    onUpdateProfile?: (data: { username: string; email: string }) => void;
}

export default function UserProfile({ username, email = '', role, onUpdateProfile }: UserProfileProps) {
    const [isEditing, setIsEditing] = useState(false);
    const [formData, setFormData] = useState({ username, email });

    const handleSave = () => {
        if (onUpdateProfile) {
            onUpdateProfile(formData);
        }
        setIsEditing(false);
    };

    const handleCancel = () => {
        setFormData({ username, email });
        setIsEditing(false);
    };

    return (
        <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="card-title flex items-center gap-2">
                        <User className="w-5 h-5" />
                        User Profile
                    </h2>
                    {!isEditing ? (
                        <button 
                            className="btn btn-sm btn-outline"
                            onClick={() => setIsEditing(true)}
                        >
                            <Edit className="w-4 h-4" />
                            Edit
                        </button>
                    ) : (
                        <div className="flex gap-2">
                            <button 
                                className="btn btn-sm btn-success"
                                onClick={handleSave}
                            >
                                <Save className="w-4 h-4" />
                                Save
                            </button>
                            <button 
                                className="btn btn-sm btn-ghost"
                                onClick={handleCancel}
                            >
                                <X className="w-4 h-4" />
                                Cancel
                            </button>
                        </div>
                    )}
                </div>

                <div className="space-y-4">
                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Username</span>
                        </label>
                        {isEditing ? (
                            <input
                                type="text"
                                className="input input-bordered"
                                value={formData.username}
                                onChange={(e) => setFormData(prev => ({
                                    ...prev,
                                    username: e.target.value
                                }))}
                            />
                        ) : (
                            <div className="input input-bordered bg-base-200 cursor-default">
                                {username}
                            </div>
                        )}
                    </div>

                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Email</span>
                        </label>
                        {isEditing ? (
                            <input
                                type="email"
                                className="input input-bordered"
                                value={formData.email}
                                onChange={(e) => setFormData(prev => ({
                                    ...prev,
                                    email: e.target.value
                                }))}
                            />
                        ) : (
                            <div className="input input-bordered bg-base-200 cursor-default">
                                {email || 'Not provided'}
                            </div>
                        )}
                    </div>

                    <div className="form-control">
                        <label className="label">
                            <span className="label-text">Role</span>
                        </label>
                        <div className="input input-bordered bg-base-200 cursor-default">
                            <span className={`badge ${role === 'admin' ? 'badge-error' : 'badge-primary'}`}>
                                {role.toUpperCase()}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}