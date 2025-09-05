// Frontend Logger - Captures console logs and sends to backend or stores locally

interface LogEntry {
    level: 'log' | 'warn' | 'error' | 'info' | 'debug';
    message: string;
    timestamp: string;
    url: string;
    userAgent: string;
    userId?: string;
    sessionId?: string;
    stack?: string;
}

class FrontendLogger {
    private logs: LogEntry[] = [];
    private maxLogs = 500;
    private batchSize = 100;
    private flushInterval = 60000; // 60 seconds
    private isEnabled = process.env.NODE_ENV === 'development'; // Only enable in development

    constructor() {
        if (typeof window !== 'undefined') {
            this.init();
            this.startAutoSave();
            this.setupUnhandledErrorCatcher();
        }
    }

    private init() {
        // Only wrap console in development mode
        if (!this.isEnabled) {
            (window as any).logger = this; // Still expose for manual use
            return;
        }

        console.log('🔧 Development mode: Frontend logging enabled');
        
        // Store original console methods
        const originalConsole = {
            log: console.log,
            warn: console.warn,
            error: console.error,
            info: console.info,
            debug: console.debug
        };

        // Wrap console methods
        console.log = (...args) => {
            this.captureLog('log', args);
            originalConsole.log.apply(console, args);
        };

        console.warn = (...args) => {
            this.captureLog('warn', args);
            originalConsole.warn.apply(console, args);
        };

        console.error = (...args) => {
            this.captureLog('error', args);
            originalConsole.error.apply(console, args);
        };

        console.info = (...args) => {
            this.captureLog('info', args);
            originalConsole.info.apply(console, args);
        };

        console.debug = (...args) => {
            this.captureLog('debug', args);
            originalConsole.debug.apply(console, args);
        };

        // Expose logger globally for manual logging
        (window as any).logger = this;
    }

    private captureLog(level: LogEntry['level'], args: any[]) {
        if (!this.isEnabled) return;

        const message = args.map(arg => 
            typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
        ).join(' ');

        const entry: LogEntry = {
            level,
            message,
            timestamp: new Date().toISOString(),
            url: window.location.href,
            userAgent: navigator.userAgent,
            userId: this.getUserId(),
            sessionId: this.getSessionId()
        };

        // Capture stack trace for errors
        if (level === 'error') {
            entry.stack = new Error().stack;
        }

        this.addLog(entry);
    }

    private addLog(entry: LogEntry) {
        this.logs.push(entry);
        
        // Keep only the most recent logs
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }

        // Auto-save on errors to ensure they're captured
        if (entry.level === 'error') {
            this.saveToLocalStorage();
        }

        // Store in localStorage as backup
        this.saveToLocalStorage();
    }

    private getUserId(): string | undefined {
        try {
            const user = localStorage.getItem('user');
            return user ? JSON.parse(user).username : undefined;
        } catch {
            return undefined;
        }
    }

    private getSessionId(): string | undefined {
        try {
            let sessionId = sessionStorage.getItem('sessionId');
            if (!sessionId) {
                sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
                sessionStorage.setItem('sessionId', sessionId);
            }
            return sessionId;
        } catch {
            return undefined;
        }
    }

    private saveToLocalStorage() {
        try {
            const recentLogs = this.logs.slice(-200); // Keep 200 most recent logs
            localStorage.setItem('frontend_logs', JSON.stringify(recentLogs));
            
            // Also save a timestamped backup
            const timestamp = new Date().toISOString().split('T')[0];
            localStorage.setItem(`frontend_logs_${timestamp}`, JSON.stringify(recentLogs));
        } catch (error) {
            // localStorage might be full or disabled
            console.warn('Failed to save logs to localStorage:', error);
        }
    }

    private startAutoSave() {
        if (!this.isEnabled) return;
        
        // Auto-save logs periodically
        setInterval(() => {
            if (this.logs.length > 0) {
                this.saveToLocalStorage();
            }
        }, this.flushInterval);

        // Export logs on page unload in development
        window.addEventListener('beforeunload', () => {
            this.saveToLocalStorage();
            
            // Auto-export if there are many logs (development only)
            if (this.logs.length > 200) {
                this.exportLogsToFile(this.logs);
            }
        });
    }

    private setupUnhandledErrorCatcher() {
        if (!this.isEnabled) return;
        
        // Catch unhandled JavaScript errors
        window.addEventListener('error', (event) => {
            this.captureLog('error', [
                'Unhandled Error:',
                event.error?.message || event.message,
                'File:', event.filename,
                'Line:', event.lineno,
                'Column:', event.colno,
                'Stack:', event.error?.stack
            ]);
        });

        // Catch unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            this.captureLog('error', [
                'Unhandled Promise Rejection:',
                event.reason
            ]);
        });
    }

    public exportLogs(): void {
        if (this.logs.length === 0) {
            console.warn('No logs to export');
            return;
        }

        this.exportLogsToFile(this.logs);
    }

    private exportLogsToFile(logs: LogEntry[]) {
        try {
            const logData = logs.map(log => 
                `[${log.timestamp}] ${log.level.toUpperCase()}: ${log.message}${log.stack ? '\n' + log.stack : ''}`
            ).join('\n\n');

            const blob = new Blob([logData], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `frontend-logs-${new Date().toISOString().split('T')[0]}.log`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.warn('Failed to export logs to file:', error);
        }
    }

    // Public methods for manual logging
    public log(message: string, data?: any) {
        this.captureLog('log', data ? [message, data] : [message]);
    }

    public warn(message: string, data?: any) {
        this.captureLog('warn', data ? [message, data] : [message]);
    }

    public error(message: string, error?: any) {
        this.captureLog('error', error ? [message, error] : [message]);
    }

    public info(message: string, data?: any) {
        this.captureLog('info', data ? [message, data] : [message]);
    }

    public debug(message: string, data?: any) {
        this.captureLog('debug', data ? [message, data] : [message]);
    }

    // Configuration methods
    public setEnabled(enabled: boolean) {
        this.isEnabled = enabled;
    }

    public setApiEndpoint(endpoint: string) {
        this.apiEndpoint = endpoint;
    }

    public getLogs(): LogEntry[] {
        return [...this.logs];
    }

    public clearLogs() {
        this.logs = [];
        localStorage.removeItem('frontend_logs');
    }

    public downloadLogs() {
        const logs = this.getLogs();
        if (logs.length === 0) {
            alert('No logs to download');
            return;
        }
        this.exportLogsToFile(logs);
    }
}

// Initialize logger only on client side
let logger: FrontendLogger;
if (typeof window !== 'undefined') {
    logger = new FrontendLogger();
}

export default logger;
export type { LogEntry };