'use client';

import { Shield, Heart, ExternalLink } from 'lucide-react';

export default function Footer() {
    const currentYear = new Date().getFullYear();

    return (
        <footer className="bg-base-100 border-t border-base-300 mt-auto">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="py-8">
                    {/* Main footer content */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
                        {/* Brand section */}
                        <div className="col-span-1 md:col-span-2">
                            <div className="flex items-center mb-4">
                                <Shield className="h-8 w-8 text-primary" />
                                <span className="ml-3 text-xl font-bold text-base-content">
                                    PropGuard
                                </span>
                            </div>
                            <p className="text-base-content/70 text-sm mb-4 max-w-md">
                                Secure secrets management and configuration service built with enterprise-grade 
                                security. Protect your sensitive data with AES-256 encryption and comprehensive 
                                audit trails.
                            </p>
                            <div className="flex items-center text-sm text-base-content/70">
                                <span>Made with</span>
                                <Heart className="h-4 w-4 mx-1 text-error fill-current" />
                                <span>for secure operations</span>
                            </div>
                        </div>

                        {/* Product links */}
                        <div>
                            <h3 className="text-sm font-semibold text-base-content mb-4">Product</h3>
                            <ul className="space-y-2 text-sm">
                                <li>
                                    <a href="/secrets" className="text-base-content/70 hover:text-primary transition-colors">
                                        Secret Management
                                    </a>
                                </li>
                                <li>
                                    <a href="/users" className="text-base-content/70 hover:text-primary transition-colors">
                                        User Management
                                    </a>
                                </li>
                                <li>
                                    <a href="/roles" className="text-base-content/70 hover:text-primary transition-colors">
                                        Role Management
                                    </a>
                                </li>
                                <li>
                                    <a href="/audit" className="text-base-content/70 hover:text-primary transition-colors">
                                        Audit Logs
                                    </a>
                                </li>
                            </ul>
                        </div>

                        {/* Support links */}
                        <div>
                            <h3 className="text-sm font-semibold text-base-content mb-4">Support</h3>
                            <ul className="space-y-2 text-sm">
                                <li>
                                    <a 
                                        href="/docs" 
                                        className="text-base-content/70 hover:text-primary transition-colors flex items-center"
                                    >
                                        Documentation
                                        <ExternalLink className="h-3 w-3 ml-1" />
                                    </a>
                                </li>
                                <li>
                                    <a 
                                        href="/api-docs" 
                                        className="text-base-content/70 hover:text-primary transition-colors flex items-center"
                                    >
                                        API Reference
                                        <ExternalLink className="h-3 w-3 ml-1" />
                                    </a>
                                </li>
                                <li>
                                    <a href="/settings" className="text-base-content/70 hover:text-primary transition-colors">
                                        System Settings
                                    </a>
                                </li>
                                <li>
                                    <a href="/health" className="text-base-content/70 hover:text-primary transition-colors">
                                        Health Status
                                    </a>
                                </li>
                            </ul>
                        </div>
                    </div>

                    {/* Bottom section */}
                    <div className="mt-8 pt-6 border-t border-base-300">
                        <div className="flex flex-col md:flex-row justify-between items-center">
                            <div className="text-sm text-base-content/70">
                                © {currentYear} PropGuard. All rights reserved.
                            </div>
                            
                            {/* Status indicators */}
                            <div className="flex items-center space-x-4 mt-4 md:mt-0">
                                <div className="flex items-center text-xs text-success">
                                    <div className="w-2 h-2 bg-success rounded-full mr-2"></div>
                                    System Online
                                </div>
                                <div className="text-xs text-base-content/70">
                                    v1.0.0-beta
                                </div>
                                <div className="text-xs text-base-content/70">
                                    BadgerDB Ready
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    );
}