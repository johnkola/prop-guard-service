'use client';

import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { 
    Menu, 
    Bell, 
    Search,
    User,
    Settings,
    LogOut,
    Shield,
    ChevronRight,
    Sun,
    Moon
} from 'lucide-react';

interface HeaderProps {
    onMenuClick: () => void;
    user: { username: string; roles: string[] } | null;
}

const breadcrumbMap: { [key: string]: string } = {
    '/': 'Dashboard',
    '/secrets': 'Secret Management',
    '/users': 'User Management',
    '/roles': 'Role Management',
    '/audit': 'Audit Logs',
    '/settings': 'Settings',
    '/profile': 'Profile'
};

export default function Header({ onMenuClick, user }: HeaderProps) {
    const [searchQuery, setSearchQuery] = useState('');
    const [theme, setTheme] = useState('light');
    const [notifications, setNotifications] = useState(0);
    const pathname = usePathname();

    // Load theme from localStorage
    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') || 'light';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
    }, []);

    // Generate breadcrumbs
    const generateBreadcrumbs = () => {
        const pathSegments = pathname.split('/').filter(segment => segment !== '');
        const breadcrumbs = [{ name: 'Home', href: '/' }];

        let currentPath = '';
        pathSegments.forEach((segment) => {
            currentPath += `/${segment}`;
            const name = breadcrumbMap[currentPath] || segment.charAt(0).toUpperCase() + segment.slice(1);
            breadcrumbs.push({ name, href: currentPath });
        });

        return breadcrumbs;
    };

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
    };

    const breadcrumbs = generateBreadcrumbs();

    return (
        <header className="bg-base-100 border-b border-base-300 sticky top-0 z-30">
            <div className="px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Left section */}
                    <div className="flex items-center">
                        {/* Mobile menu button */}
                        <button
                            onClick={onMenuClick}
                            className="btn btn-ghost btn-square lg:hidden"
                            aria-label="Open sidebar"
                        >
                            <Menu className="h-5 w-5" />
                        </button>

                        {/* Breadcrumbs */}
                        <nav className="hidden sm:flex ml-4 lg:ml-0" aria-label="Breadcrumb">
                            <ol className="flex items-center space-x-2">
                                {breadcrumbs.map((crumb, index) => (
                                    <li key={crumb.href} className="flex items-center">
                                        {index > 0 && (
                                            <ChevronRight className="h-4 w-4 text-base-content/40 mx-2" />
                                        )}
                                        {index === breadcrumbs.length - 1 ? (
                                            <span className="text-sm font-medium text-base-content">
                                                {crumb.name}
                                            </span>
                                        ) : (
                                            <a
                                                href={crumb.href}
                                                className="text-sm font-medium text-base-content/70 hover:text-base-content transition-colors"
                                            >
                                                {crumb.name}
                                            </a>
                                        )}
                                    </li>
                                ))}
                            </ol>
                        </nav>
                    </div>

                    {/* Center - Search (hidden on mobile) */}
                    <div className="hidden md:flex flex-1 max-w-md mx-8">
                        <div className="form-control w-full">
                            <div className="input-group">
                                <span>
                                    <Search className="h-4 w-4" />
                                </span>
                                <input
                                    type="text"
                                    placeholder="Search secrets, users, roles..."
                                    className="input input-bordered w-full"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                />
                            </div>
                        </div>
                    </div>

                    {/* Right section */}
                    <div className="flex items-center space-x-2">
                        {/* Theme toggle */}
                        <button
                            onClick={toggleTheme}
                            className="btn btn-ghost btn-square"
                            aria-label="Toggle theme"
                        >
                            {theme === 'light' ? (
                                <Moon className="h-5 w-5" />
                            ) : (
                                <Sun className="h-5 w-5" />
                            )}
                        </button>

                        {/* Notifications */}
                        <div className="dropdown dropdown-end">
                            <button
                                tabIndex={0}
                                className="btn btn-ghost btn-square"
                                aria-label="Notifications"
                            >
                                <div className="indicator">
                                    <Bell className="h-5 w-5" />
                                    {notifications > 0 && (
                                        <span className="badge badge-primary badge-xs indicator-item">
                                            {notifications > 9 ? '9+' : notifications}
                                        </span>
                                    )}
                                </div>
                            </button>
                            <div
                                tabIndex={0}
                                className="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-80"
                            >
                                <div className="menu-title">
                                    <span>Notifications</span>
                                </div>
                                <div className="p-4 text-center text-base-content/70">
                                    No new notifications
                                </div>
                            </div>
                        </div>

                        {/* User menu */}
                        <div className="dropdown dropdown-end">
                            <button
                                tabIndex={0}
                                className="btn btn-ghost flex items-center space-x-2"
                                aria-label="User menu"
                            >
                                <div className="avatar placeholder">
                                    <div className="bg-primary text-primary-content rounded-full w-8">
                                        <span className="text-xs">
                                            {user?.username?.[0]?.toUpperCase() || 'U'}
                                        </span>
                                    </div>
                                </div>
                                <div className="hidden md:block text-left">
                                    <div className="text-sm font-medium text-base-content">
                                        {user?.username || 'User'}
                                    </div>
                                    <div className="text-xs text-base-content/70">
                                        {user?.roles?.[0] || 'No role'}
                                    </div>
                                </div>
                            </button>
                            <ul
                                tabIndex={0}
                                className="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-52"
                            >
                                <li className="menu-title">
                                    <span>{user?.username || 'User'}</span>
                                </li>
                                <li>
                                    <a href="/profile">
                                        <User className="h-4 w-4" />
                                        Profile
                                    </a>
                                </li>
                                <li>
                                    <a href="/settings">
                                        <Settings className="h-4 w-4" />
                                        Settings
                                    </a>
                                </li>
                                <div className="divider my-1"></div>
                                <li>
                                    <button onClick={handleLogout} className="text-error">
                                        <LogOut className="h-4 w-4" />
                                        Logout
                                    </button>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>

                {/* Mobile search */}
                <div className="md:hidden pb-4">
                    <div className="form-control">
                        <div className="input-group">
                            <span>
                                <Search className="h-4 w-4" />
                            </span>
                            <input
                                type="text"
                                placeholder="Search..."
                                className="input input-bordered w-full"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                            />
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
}