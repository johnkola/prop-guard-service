'use client';

import { useState, useEffect } from 'react';
import { 
    FileText, 
    Search, 
    Filter, 
    RefreshCw, 
    Download, 
    Calendar,
    User,
    Activity,
    CheckCircle,
    XCircle,
    Clock,
    ChevronDown,
    ChevronRight
} from 'lucide-react';
import Pagination from '../../components/Pagination';
import { ApiClient } from '../../lib/api';

interface AuditLog {
    id: string;
    username: string;
    action: string;
    path: string;
    success: boolean;
    timestamp: string;
    details?: string;
    errorMessage?: string;
    clientIP?: string;
    userAgent?: string;
}

export default function AuditViewer() {
    const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [actionFilter, setActionFilter] = useState<string>('all');
    const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'failure'>('all');
    const [dateRange, setDateRange] = useState({ from: '', to: '' });
    const [refreshing, setRefreshing] = useState(false);
    const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set());
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(20);
    const [totalItems, setTotalItems] = useState(0);

    // Load audit logs from API
    const loadAuditLogs = async (page = currentPage, resetPage = false) => {
        try {
            setRefreshing(true);
            if (resetPage) {
                setCurrentPage(1);
                page = 1;
            }
            
            const queryParams = new URLSearchParams({
                page: page.toString(),
                pageSize: itemsPerPage.toString(),
            });

            if (searchTerm) queryParams.set('search', searchTerm);
            if (actionFilter !== 'all') queryParams.set('action', actionFilter);
            if (statusFilter !== 'all') queryParams.set('success', statusFilter === 'success' ? 'true' : 'false');
            if (dateRange.from) queryParams.set('from', dateRange.from);
            if (dateRange.to) queryParams.set('to', dateRange.to);

            const response = await ApiClient.get<{logs: AuditLog[], total: number}>(`/v1/audit?${queryParams}`);
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            const logs = response.data?.logs || [];
            setAuditLogs(logs); // Replace instead of appending for pagination
            setTotalItems(response.data?.total || 0);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load audit logs');
            // Set mock data if API fails
            if (auditLogs.length === 0) {
                setAuditLogs([
                    {
                        id: '1',
                        username: 'admin',
                        action: 'CREATE_SECRET',
                        path: '/app/database/password',
                        success: true,
                        timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
                        details: 'Created new database password secret',
                        clientIP: '192.168.1.100',
                        userAgent: 'Mozilla/5.0...',
                    },
                    {
                        id: '2',
                        username: 'user1',
                        action: 'READ_SECRET',
                        path: '/app/api/key',
                        success: false,
                        timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
                        errorMessage: 'Permission denied: insufficient privileges',
                        clientIP: '192.168.1.101',
                        userAgent: 'curl/7.68.0',
                    },
                    {
                        id: '3',
                        username: 'admin',
                        action: 'LOGIN',
                        path: '',
                        success: true,
                        timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
                        details: 'Successful administrator login',
                        clientIP: '192.168.1.100',
                    },
                ]);
                setTotalItems(3); // Mock data count
            }
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    // Handle page change
    const handlePageChange = (page: number) => {
        setCurrentPage(page);
        loadAuditLogs(page);
    };

    // Handle items per page change
    const handleItemsPerPageChange = (newItemsPerPage: number) => {
        setItemsPerPage(newItemsPerPage);
        setCurrentPage(1);
    };

    // Export audit logs
    const exportLogs = async () => {
        try {
            const queryParams = new URLSearchParams();
            if (searchTerm) queryParams.set('search', searchTerm);
            if (actionFilter !== 'all') queryParams.set('action', actionFilter);
            if (statusFilter !== 'all') queryParams.set('success', statusFilter === 'success' ? 'true' : 'false');
            if (dateRange.from) queryParams.set('from', dateRange.from);
            if (dateRange.to) queryParams.set('to', dateRange.to);

            const response = await ApiClient.get(`/v1/audit/export?${queryParams}`);
            
            if (response.error) {
                throw new Error(response.error);
            }

            // Create and download CSV file
            const csv = convertToCSV(auditLogs);
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to export audit logs');
        }
    };

    const convertToCSV = (logs: AuditLog[]): string => {
        const headers = ['Timestamp', 'Username', 'Action', 'Path', 'Success', 'Details', 'Client IP', 'User Agent'];
        const rows = logs.map(log => [
            log.timestamp,
            log.username,
            log.action,
            log.path,
            log.success.toString(),
            log.details || log.errorMessage || '',
            log.clientIP || '',
            log.userAgent || ''
        ]);
        
        return [headers, ...rows].map(row => 
            row.map(field => `"${field.toString().replace(/"/g, '""')}"`).join(',')
        ).join('\n');
    };

    const toggleLogExpansion = (logId: string) => {
        setExpandedLogs(prev => {
            const newSet = new Set(prev);
            if (newSet.has(logId)) {
                newSet.delete(logId);
            } else {
                newSet.add(logId);
            }
            return newSet;
        });
    };

    const getActionColor = (action: string) => {
        if (action.includes('CREATE')) return 'badge-success';
        if (action.includes('DELETE')) return 'badge-error';
        if (action.includes('UPDATE')) return 'badge-warning';
        if (action.includes('READ') || action.includes('LIST')) return 'badge-info';
        if (action.includes('LOGIN')) return 'badge-primary';
        return 'badge-neutral';
    };

    const formatTimestamp = (timestamp: string) => {
        const date = new Date(timestamp);
        return {
            date: date.toLocaleDateString(),
            time: date.toLocaleTimeString(),
        };
    };

    const uniqueActions = [...new Set(auditLogs.map(log => log.action))];

    // Calculate total pages
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    // Load data on component mount and when filters/pagination change
    useEffect(() => {
        loadAuditLogs(currentPage, searchTerm || actionFilter !== 'all' || statusFilter !== 'all');
    }, [currentPage, itemsPerPage, searchTerm, actionFilter, statusFilter, dateRange]);

    if (loading && auditLogs.length === 0) {
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
                    <FileText className="w-6 h-6" />
                    <h1 className="text-2xl font-bold">Audit Logs</h1>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={exportLogs}
                        title="Export audit logs"
                    >
                        <Download className="w-4 h-4" />
                        Export
                    </button>
                    <button
                        className={`btn btn-ghost btn-sm ${refreshing ? 'loading' : ''}`}
                        onClick={() => loadAuditLogs(true)}
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

            {/* Filters */}
            <div className="card bg-base-100 shadow-sm">
                <div className="card-body py-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        {/* Search */}
                        <div className="form-control">
                            <div className="input-group">
                                <span>
                                    <Search className="w-4 h-4" />
                                </span>
                                <input
                                    type="text"
                                    className="input input-bordered input-sm flex-1"
                                    placeholder="Search logs..."
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                />
                            </div>
                        </div>

                        {/* Action Filter */}
                        <div className="form-control">
                            <select 
                                className="select select-bordered select-sm"
                                value={actionFilter}
                                onChange={(e) => setActionFilter(e.target.value)}
                            >
                                <option value="all">All Actions</option>
                                {uniqueActions.map(action => (
                                    <option key={action} value={action}>{action}</option>
                                ))}
                            </select>
                        </div>

                        {/* Status Filter */}
                        <div className="form-control">
                            <select 
                                className="select select-bordered select-sm"
                                value={statusFilter}
                                onChange={(e) => setStatusFilter(e.target.value as 'all' | 'success' | 'failure')}
                            >
                                <option value="all">All Status</option>
                                <option value="success">Success Only</option>
                                <option value="failure">Failure Only</option>
                            </select>
                        </div>

                        {/* Results Count */}
                        <div className="flex items-center text-sm text-base-content/70">
                            {filteredLogs.length} of {auditLogs.length} logs
                        </div>
                    </div>
                </div>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="stat bg-base-100 shadow-sm rounded-lg">
                    <div className="stat-title">Total Logs</div>
                    <div className="stat-value text-primary">{auditLogs.length}</div>
                </div>
                <div className="stat bg-base-100 shadow-sm rounded-lg">
                    <div className="stat-title">Successful</div>
                    <div className="stat-value text-success">{auditLogs.filter(log => log.success).length}</div>
                </div>
                <div className="stat bg-base-100 shadow-sm rounded-lg">
                    <div className="stat-title">Failed</div>
                    <div className="stat-value text-error">{auditLogs.filter(log => !log.success).length}</div>
                </div>
                <div className="stat bg-base-100 shadow-sm rounded-lg">
                    <div className="stat-title">Unique Users</div>
                    <div className="stat-value text-info">{new Set(auditLogs.map(log => log.username)).size}</div>
                </div>
            </div>

            {/* Audit Logs List */}
            <div className="card bg-base-100 shadow-xl">
                <div className="card-body p-0">
                    {auditLogs.length === 0 ? (
                        <div className="text-center py-12 text-base-content/60">
                            <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                            <p>No audit logs found</p>
                            <p className="text-sm">Try adjusting your search filters</p>
                        </div>
                    ) : (
                        <div className="space-y-1">
                            {auditLogs.map((log) => {
                                const { date, time } = formatTimestamp(log.timestamp);
                                const isExpanded = expandedLogs.has(log.id);
                                
                                return (
                                    <div 
                                        key={log.id} 
                                        className={`border-b border-base-200 last:border-b-0 hover:bg-base-50 transition-colors ${!log.success ? 'bg-error/5' : ''}`}
                                    >
                                        <div 
                                            className="p-4 cursor-pointer"
                                            onClick={() => toggleLogExpansion(log.id)}
                                        >
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-4 flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                                                        {log.success ? (
                                                            <CheckCircle className="w-5 h-5 text-success" />
                                                        ) : (
                                                            <XCircle className="w-5 h-5 text-error" />
                                                        )}
                                                    </div>
                                                    
                                                    <div className="flex items-center gap-2 min-w-0">
                                                        <User className="w-4 h-4 text-base-content/50 flex-shrink-0" />
                                                        <span className="font-medium truncate">{log.username}</span>
                                                    </div>
                                                    
                                                    <span className={`badge badge-sm ${getActionColor(log.action)}`}>
                                                        {log.action}
                                                    </span>
                                                    
                                                    {log.path && (
                                                        <div className="font-mono text-sm text-base-content/70 truncate">
                                                            {log.path}
                                                        </div>
                                                    )}
                                                </div>
                                                
                                                <div className="flex items-center gap-2 text-sm text-base-content/60 flex-shrink-0">
                                                    <Clock className="w-4 h-4" />
                                                    <span>{date}</span>
                                                    <span>{time}</span>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {isExpanded && (
                                            <div className="px-4 pb-4 border-t border-base-200 bg-base-50">
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                                                    {log.details && (
                                                        <div>
                                                            <span className="font-semibold text-sm">Details:</span>
                                                            <p className="text-sm text-base-content/70 mt-1">{log.details}</p>
                                                        </div>
                                                    )}
                                                    
                                                    {log.errorMessage && (
                                                        <div>
                                                            <span className="font-semibold text-sm text-error">Error:</span>
                                                            <p className="text-sm text-error/70 mt-1">{log.errorMessage}</p>
                                                        </div>
                                                    )}
                                                    
                                                    {log.clientIP && (
                                                        <div>
                                                            <span className="font-semibold text-sm">Client IP:</span>
                                                            <p className="text-sm text-base-content/70 mt-1 font-mono">{log.clientIP}</p>
                                                        </div>
                                                    )}
                                                    
                                                    {log.userAgent && (
                                                        <div className="md:col-span-2">
                                                            <span className="font-semibold text-sm">User Agent:</span>
                                                            <p className="text-sm text-base-content/70 mt-1 font-mono truncate">{log.userAgent}</p>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
            
            {/* Pagination */}
            {totalItems > 0 && (
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
            )}
        </div>
    );
}