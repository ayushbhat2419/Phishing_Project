/**
 * API Client Service
 * Communicates with the Flask REST API backend under /api/v1
 */

const BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  try {
    const response = await fetch(url, { ...options, headers });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || data.details || data.error || `HTTP error ${response.status}`);
    }

    return data;
  } catch (error) {
    console.error(`API Error on [${options.method || 'GET'} ${endpoint}]:`, error);
    throw error;
  }
}

export const api = {
  // Scans
  scanUrl: (url) => request('/scan/url', { method: 'POST', body: JSON.stringify({ url }) }),
  scanEmail: ({ subject, body, sender }) => request('/scan/email', { method: 'POST', body: JSON.stringify({ subject, body, sender }) }),

  // Analytics & History
  getDashboardStats: () => request('/dashboard/stats'),
  getScanHistory: (page = 1, limit = 20, type = '', verdict = '') => {
    const params = new URLSearchParams({ page, limit });
    if (type) params.append('type', type);
    if (verdict) params.append('verdict', verdict);
    return request(`/history?${params.toString()}`);
  },
  getScanDetail: (id) => request(`/history/${id}`),

  // Models & System
  getModelMetrics: () => request('/models/metrics'),
  getHealth: () => request('/health')
};

export default api;
