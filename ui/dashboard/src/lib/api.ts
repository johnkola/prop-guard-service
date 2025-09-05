// API utility for communicating with PropGuard backend
const API_BASE_URL = '/api/v1';

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

export class ApiClient {
  private static async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      });

      const data = await response.json();

      return {
        data: response.ok ? data : undefined,
        error: response.ok ? undefined : data.error || `HTTP ${response.status}`,
        status: response.status,
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : 'Network error',
        status: 0,
      };
    }
  }

  // Health check
  static async getHealth() {
    return this.request<{ status: string; time: number; database: string }>('/health');
  }

  // App info
  static async getInfo() {
    return this.request<{ app: string; version: string; status: string }>('/info');
  }

  // Generic GET request
  static async get<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  // Generic POST request
  static async post<T>(endpoint: string, body: any) {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // Generic PUT request
  static async put<T>(endpoint: string, body: any) {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  // Generic DELETE request
  static async delete<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }

  // Auth endpoints
  static async login(username: string, password: string) {
    return this.request<{ token: string; user: any }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  static async logout() {
    const token = localStorage.getItem('token');
    return this.request<{ message: string }>('/auth/logout', {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  }

  static async refreshToken() {
    const token = localStorage.getItem('token');
    return this.request<{ token: string }>('/auth/refresh', {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  }

  // Authenticated requests helper
  static async authenticatedRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const token = localStorage.getItem('token');
    
    const authOptions = {
      ...options,
      headers: {
        ...options.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    };

    return this.request<T>(endpoint, authOptions);
  }

  // Authenticated GET
  static async authGet<T>(endpoint: string) {
    return this.authenticatedRequest<T>(endpoint, { method: 'GET' });
  }

  // Authenticated POST
  static async authPost<T>(endpoint: string, body: any) {
    return this.authenticatedRequest<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // Authenticated PUT
  static async authPut<T>(endpoint: string, body: any) {
    return this.authenticatedRequest<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  // Authenticated DELETE
  static async authDelete<T>(endpoint: string) {
    return this.authenticatedRequest<T>(endpoint, { method: 'DELETE' });
  }
}