'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { 
    Shield, 
    Key, 
    Users, 
    UserCheck,
    FileText,
    Settings,
    Home,
    LogOut,
    ChevronRight,
    X
} from 'lucide-react';

interface SidebarProps {
    open: boolean;
    onClose: () => void;
    user: { username: string; roles: string[] } | null;
}

interface NavItem {
    name: string;
    href: string;
    icon: React.ComponentType<{ className?: string }>;
    roles?: string[];
    badge?: string;
}

const navigation: NavItem[] = [
    {
        name: 'Dashboard',
        href: '/',
        icon: Home,
    },
    {
        name: 'Secrets',
        href: '/secrets',
        icon: Key,
        badge: 'Core'
    },
    {
        name: 'Users',
        href: '/users',
        icon: Users,
        roles: ['admin', 'user_manager']
    },
    {
        name: 'Roles',
        href: '/roles',
        icon: UserCheck,
        roles: ['admin']
    },
    {
        name: 'Audit Logs',
        href: '/audit',
        icon: FileText,
        roles: ['admin', 'auditor']
    },
    {
        name: 'Settings',
        href: '/settings',
        icon: Settings,
        roles: ['admin']
    }
];

export default function Sidebar({ open, onClose, user }: SidebarProps) {
    const pathname = usePathname();

    const canAccess = (item: NavItem): boolean => {
        if (!item.roles) return true;
        if (!user?.roles) return false;
        return item.roles.some(role => user.roles.includes(role)) || user.roles.includes('admin');
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
    };

    return (
        <>
            {/* Desktop Sidebar */}
            <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
                <div className="flex flex-col flex-grow bg-base-100 border-r border-base-300 overflow-y-auto">
                    {/* Logo */}
                    <div className="flex items-center flex-shrink-0 px-6 py-4 border-b border-base-300">
                        <Shield className="h-8 w-8 text-primary" />
                        <span className="ml-3 text-xl font-bold text-base-content">
                            PropGuard
                        </span>
                    </div>

                    {/* Navigation */}
                    <nav className="flex-1 px-4 py-6 space-y-2">
                        {navigation.map((item) => {
                            if (!canAccess(item)) return null;
                            
                            const isActive = pathname === item.href;
                            const Icon = item.icon;

                            return (
                                <Link
                                    key={item.name}
                                    href={item.href}
                                    className={`
                                        group flex items-center px-3 py-2 text-sm font-medium rounded-lg
                                        transition-colors duration-200
                                        ${isActive 
                                            ? 'bg-primary text-primary-content' 
                                            : 'text-base-content hover:bg-base-200'
                                        }
                                    `}
                                >
                                    <Icon 
                                        className={`mr-3 h-5 w-5 ${
                                            isActive ? 'text-primary-content' : 'text-base-content/70'
                                        }`} 
                                    />
                                    {item.name}
                                    {item.badge && (
                                        <span className="ml-auto">
                                            <span className="badge badge-primary badge-sm">
                                                {item.badge}
                                            </span>
                                        </span>
                                    )}
                                    {isActive && (
                                        <ChevronRight className="ml-auto h-4 w-4" />
                                    )}
                                </Link>
                            );
                        })}
                    </nav>

                    {/* User section */}
                    <div className="flex-shrink-0 border-t border-base-300 p-4">
                        <div className="flex items-center">
                            <div className="avatar placeholder">
                                <div className="bg-primary text-primary-content rounded-full w-10">
                                    <span className="text-sm">
                                        {user?.username?.[0]?.toUpperCase() || 'U'}
                                    </span>
                                </div>
                            </div>
                            <div className="ml-3 flex-1 min-w-0">
                                <p className="text-sm font-medium text-base-content truncate">
                                    {user?.username || 'User'}
                                </p>
                                <p className="text-xs text-base-content/70 truncate">
                                    {user?.roles?.join(', ') || 'No roles'}
                                </p>
                            </div>
                            <button
                                onClick={handleLogout}
                                className="btn btn-ghost btn-sm btn-square"
                                title="Logout"
                            >
                                <LogOut className="h-4 w-4" />
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Mobile Sidebar */}
            <div className={`lg:hidden fixed inset-0 z-50 ${open ? '' : 'pointer-events-none'}`}>
                <div className={`fixed inset-y-0 left-0 w-64 bg-base-100 border-r border-base-300 transform transition-transform duration-300 ease-in-out ${
                    open ? 'translate-x-0' : '-translate-x-full'
                }`}>
                    {/* Mobile header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-base-300">
                        <div className="flex items-center">
                            <Shield className="h-8 w-8 text-primary" />
                            <span className="ml-3 text-xl font-bold text-base-content">
                                PropGuard
                            </span>
                        </div>
                        <button
                            onClick={onClose}
                            className="btn btn-ghost btn-sm btn-square"
                        >
                            <X className="h-5 w-5" />
                        </button>
                    </div>

                    {/* Mobile Navigation */}
                    <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
                        {navigation.map((item) => {
                            if (!canAccess(item)) return null;
                            
                            const isActive = pathname === item.href;
                            const Icon = item.icon;

                            return (
                                <Link
                                    key={item.name}
                                    href={item.href}
                                    onClick={onClose}
                                    className={`
                                        group flex items-center px-3 py-2 text-sm font-medium rounded-lg
                                        transition-colors duration-200
                                        ${isActive 
                                            ? 'bg-primary text-primary-content' 
                                            : 'text-base-content hover:bg-base-200'
                                        }
                                    `}
                                >
                                    <Icon 
                                        className={`mr-3 h-5 w-5 ${
                                            isActive ? 'text-primary-content' : 'text-base-content/70'
                                        }`} 
                                    />
                                    {item.name}
                                    {item.badge && (
                                        <span className="ml-auto">
                                            <span className="badge badge-primary badge-sm">
                                                {item.badge}
                                            </span>
                                        </span>
                                    )}
                                </Link>
                            );
                        })}
                    </nav>

                    {/* Mobile user section */}
                    <div className="border-t border-base-300 p-4">
                        <div className="flex items-center mb-4">
                            <div className="avatar placeholder">
                                <div className="bg-primary text-primary-content rounded-full w-10">
                                    <span className="text-sm">
                                        {user?.username?.[0]?.toUpperCase() || 'U'}
                                    </span>
                                </div>
                            </div>
                            <div className="ml-3 flex-1 min-w-0">
                                <p className="text-sm font-medium text-base-content truncate">
                                    {user?.username || 'User'}
                                </p>
                                <p className="text-xs text-base-content/70 truncate">
                                    {user?.roles?.join(', ') || 'No roles'}
                                </p>
                            </div>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="btn btn-error btn-sm w-full"
                        >
                            <LogOut className="h-4 w-4 mr-2" />
                            Logout
                        </button>
                    </div>
                </div>
            </div>
        </>
    );
}