'use client';

import { useState, useEffect } from 'react';
import Dashboard from '../components/Dashboard';
import DashboardLayout from '../components/layout/DashboardLayout';

export default function Home() {
    const [token, setToken] = useState<string | null>(null);
    const [theme, setTheme] = useState('light');

    useEffect(() => {
        // Load token and theme
        const storedToken = localStorage.getItem('token');
        const storedTheme = localStorage.getItem('theme') || 'light';
        
        setToken(storedToken);
        setTheme(storedTheme);
        document.documentElement.setAttribute('data-theme', storedTheme);
    }, []);

    const handleLogout = () => {
        // Clear authentication
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        
        // Redirect to login
        window.location.href = '/login';
    };

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    return (
        <DashboardLayout>
            <Dashboard
                token={token || ''}
                onLogout={handleLogout}
                theme={theme}
                toggleTheme={toggleTheme}
            />
        </DashboardLayout>
    );
}