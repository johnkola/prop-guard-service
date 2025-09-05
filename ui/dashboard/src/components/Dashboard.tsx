'use client';

import { useState, useEffect } from 'react';
import { ApiClient } from '../lib/api';
import {
    LogOut,
    Sun,
    Moon,
    Key,
    Users,
    Shield,
    FileText,
    BarChart3,
    Settings,
    Bell,
    Search,
    Plus,
    TrendingUp,
    Lock,
    Calendar,
    AlertCircle
} from 'lucide-react';
import SecretManager from '../modules/secret-vault/SecretManager';
import UserManager from '../modules/user-mgmt/UserManager';
import RoleManager from '../modules/role-mgmt/RoleManager';
import AuditViewer from '../modules/audit/AuditViewer';

interface DashboardProps {
    token: string;
    onLogout: () => void;
    theme: string;
    toggleTheme: () => void;
}

export default function Dashboard({ token, onLogout, theme, toggleTheme }: DashboardProps) {
    const [activeTab, setActiveTab] = useState('overview');
    const [apiStatus, setApiStatus] = useState<string>('checking');
    const [appInfo, setAppInfo] = useState<any>(null);
    const [userInfo, setUserInfo] = useState<any>(null);

    // Get user info from localStorage instead of decoding token
    useEffect(() => {
        const userData = localStorage.getItem('user');
        if (userData) {
            try {
                setUserInfo(JSON.parse(userData));
            } catch (error) {
                console.error('Error parsing user data:', error);
                // Fallback user info
                setUserInfo({ username: 'admin', roles: ['admin'], id: 'user_admin' });
            }
        } else {
            // Fallback user info if no data in localStorage
            setUserInfo({ username: 'admin', roles: ['admin'], id: 'user_admin' });
        }
    }, []);

    // Check API connection on component mount
    useEffect(() => {
        const checkApiConnection = async () => {
            try {
                const healthResponse = await ApiClient.getHealth();
                const infoResponse = await ApiClient.getInfo();
                
                if (healthResponse.data) {
                    setApiStatus('connected');
                    console.log('✅ Backend API connected:', healthResponse.data);
                } else {
                    setApiStatus('error');
                    console.error('❌ Backend API error:', healthResponse.error);
                }

                if (infoResponse.data) {
                    setAppInfo(infoResponse.data);
                    console.log('ℹ️ App info:', infoResponse.data);
                }
            } catch (error) {
                setApiStatus('error');
                console.error('❌ API connection failed:', error);
            }
        };

        checkApiConnection();
    }, []);

    const stats = [
        {
            title: 'Total Secrets',
            value: '156',
            change: '+8.2%',
            icon: Key,
            color: 'text-primary'
        },
        {
            title: 'Active Users',
            value: '23',
            change: '+4.1%',
            icon: Users,
            color: 'text-success'
        },
        {
            title: 'Custom Roles',
            value: '12',
            change: '+2.0%',
            icon: Shield,
            color: 'text-info'
        },
        {
            title: 'Failed Access',
            value: '3',
            change: '-25.0%',
            icon: AlertCircle,
            color: 'text-warning'
        },
    ];

    const recentActivities = [
        { type: 'secret', message: 'New secret created: /app/database/password', time: '2 hours ago' },
        { type: 'user', message: 'User "developer1" login successful', time: '4 hours ago' },
        { type: 'role', message: 'Role "DevOps" assigned to user "admin2"', time: '6 hours ago' },
        { type: 'audit', message: 'Failed access attempt to /prod/api-key', time: '1 day ago' },
    ];

    return (
        <div className="min-h-screen bg-base-200">
            {/* Navigation Header */}
            <div className="navbar bg-base-100 shadow-lg">
                <div className="navbar-start">
                    <div className="flex items-center">
                        <Lock className="w-8 h-8 text-primary mr-3" />
                        <span className="text-xl font-bold">PropGuard</span>
                    </div>
                </div>

                <div className="navbar-center hidden lg:flex">
                    <div className="form-control">
                        <div className="input-group">
                            <input
                                type="text"
                                placeholder="Search secrets, users, roles..."
                                className="input input-bordered w-64"
                            />
                            <button className="btn btn-square">
                                <Search className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </div>

                <div className="navbar-end">
                    {/* API Status Indicator */}
                    <div className={`badge ${apiStatus === 'connected' ? 'badge-success' : apiStatus === 'error' ? 'badge-error' : 'badge-warning'} mr-4`}>
                        {apiStatus === 'connected' && '🟢 API'}
                        {apiStatus === 'error' && '🔴 API'}
                        {apiStatus === 'checking' && '🟡 API'}
                    </div>

                    <button className="btn btn-ghost btn-circle">
                        <div className="indicator">
                            <Bell className="w-5 h-5" />
                            <span className="badge badge-xs badge-primary indicator-item">3</span>
                        </div>
                    </button>

                    <button
                        className="btn btn-ghost btn-circle ml-2"
                        onClick={toggleTheme}
                    >
                        {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                    </button>

                    <div className="dropdown dropdown-end ml-2">
                        <div tabIndex={0} role="button" className="btn btn-ghost btn-circle avatar">
                            <div className="w-10 rounded-full bg-primary text-primary-content flex items-center justify-center">
                                {userInfo?.username?.charAt(0).toUpperCase() || 'U'}
                            </div>
                        </div>
                        <ul tabIndex={0} className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
                            <li><a className="justify-between">Profile <span className="badge">Admin</span></a></li>
                            <li><a>Settings</a></li>
                            <li><button onClick={onLogout}><LogOut className="w-4 h-4" />Logout</button></li>
                        </ul>
                    </div>
                </div>
            </div>

            <div className="flex">
                {/* Sidebar */}
                <div className="w-64 min-h-screen bg-base-100 shadow-lg">
                    <div className="menu p-4">
                        <li>
                            <a
                                className={`${activeTab === 'overview' ? 'active' : ''}`}
                                onClick={() => setActiveTab('overview')}
                            >
                                <BarChart3 className="w-5 h-5" />
                                Overview
                            </a>
                        </li>
                        <li>
                            <a
                                className={`${activeTab === 'secrets' ? 'active' : ''}`}
                                onClick={() => setActiveTab('secrets')}
                            >
                                <Key className="w-5 h-5" />
                                Secrets
                            </a>
                        </li>
                        <li>
                            <a
                                className={`${activeTab === 'users' ? 'active' : ''}`}
                                onClick={() => setActiveTab('users')}
                            >
                                <Users className="w-5 h-5" />
                                Users
                            </a>
                        </li>
                        <li>
                            <a
                                className={`${activeTab === 'roles' ? 'active' : ''}`}
                                onClick={() => setActiveTab('roles')}
                            >
                                <Shield className="w-5 h-5" />
                                Roles
                            </a>
                        </li>
                        <li>
                            <a
                                className={`${activeTab === 'audit' ? 'active' : ''}`}
                                onClick={() => setActiveTab('audit')}
                            >
                                <FileText className="w-5 h-5" />
                                Audit Logs
                            </a>
                        </li>
                        <li>
                            <a
                                className={`${activeTab === 'settings' ? 'active' : ''}`}
                                onClick={() => setActiveTab('settings')}
                            >
                                <Settings className="w-5 h-5" />
                                Settings
                            </a>
                        </li>
                    </div>
                </div>

                {/* Main Content */}
                <div className="flex-1 p-6">
                    {activeTab === 'overview' && (
                        <div className="space-y-6">
                            {/* Header */}
                            <div className="flex justify-between items-center">
                                <div>
                                    <h1 className="text-3xl font-bold">Dashboard Overview</h1>
                                    <p className="text-base-content/60">Welcome back, {userInfo?.username || 'User'}!</p>
                                </div>
                                <button className="btn btn-primary">
                                    <Plus className="w-5 h-5 mr-2" />
                                    Add Secret
                                </button>
                            </div>

                            {/* Stats Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                                {stats.map((stat, index) => (
                                    <div key={index} className="card bg-base-100 shadow-lg">
                                        <div className="card-body">
                                            <div className="flex items-center justify-between">
                                                <div>
                                                    <p className="text-base-content/60 text-sm">{stat.title}</p>
                                                    <p className="text-2xl font-bold">{stat.value}</p>
                                                    <div className="flex items-center mt-1">
                                                        <TrendingUp className="w-4 h-4 text-success mr-1" />
                                                        <span className="text-success text-sm">{stat.change}</span>
                                                    </div>
                                                </div>
                                                <div className={`p-3 rounded-full bg-base-200 ${stat.color}`}>
                                                    <stat.icon className="w-6 h-6" />
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* Charts and Activities */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                {/* Access Trends Chart Placeholder */}
                                <div className="card bg-base-100 shadow-lg">
                                    <div className="card-body">
                                        <h2 className="card-title">Secret Access Trends</h2>
                                        <div className="h-64 bg-base-200 rounded-lg flex items-center justify-center">
                                            <div className="text-center text-base-content/60">
                                                <BarChart3 className="w-12 h-12 mx-auto mb-2" />
                                                <p>Access analytics will be displayed here</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Recent Activities */}
                                <div className="card bg-base-100 shadow-lg">
                                    <div className="card-body">
                                        <h2 className="card-title">Recent Activities</h2>
                                        <div className="space-y-4">
                                            {recentActivities.map((activity, index) => (
                                                <div key={index} className="flex items-start space-x-3">
                                                    <div className={`p-2 rounded-full ${
                                                        activity.type === 'secret' ? 'bg-success/20 text-success' :
                                                            activity.type === 'user' ? 'bg-warning/20 text-warning' :
                                                                activity.type === 'role' ? 'bg-info/20 text-info' :
                                                                    'bg-error/20 text-error'
                                                    }`}>
                                                        {activity.type === 'secret' && <Key className="w-4 h-4" />}
                                                        {activity.type === 'user' && <Users className="w-4 h-4" />}
                                                        {activity.type === 'role' && <Shield className="w-4 h-4" />}
                                                        {activity.type === 'audit' && <AlertCircle className="w-4 h-4" />}
                                                    </div>
                                                    <div className="flex-1">
                                                        <p className="text-sm">{activity.message}</p>
                                                        <p className="text-xs text-base-content/60">{activity.time}</p>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Secrets Management Tab */}
                    {activeTab === 'secrets' && <SecretManager />}

                    {/* Users Management Tab */}
                    {activeTab === 'users' && <UserManager />}

                    {/* Roles Management Tab */}
                    {activeTab === 'roles' && <RoleManager />}

                    {/* Audit Logs Tab */}
                    {activeTab === 'audit' && <AuditViewer />}

                    {/* Settings Tab */}
                    {activeTab === 'settings' && (
                        <div className="space-y-6">
                            <div className="flex items-center gap-2">
                                <Settings className="w-6 h-6" />
                                <h1 className="text-2xl font-bold">Settings</h1>
                            </div>
                            <div className="text-center py-20">
                                <div className="text-base-content/60">
                                    <Settings className="w-16 h-16 mx-auto mb-4" />
                                    <h2 className="text-2xl font-bold mb-2">System Settings</h2>
                                    <p>Configuration settings will be displayed here.</p>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}