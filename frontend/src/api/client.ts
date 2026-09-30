import axios from 'axios';

const API_BASE_URL = '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach JWT Bearer token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('pki_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Response interceptor: log errors without forcibly logging out the user
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Preserve session even if a specific API call encounters an authorization/role error
    return Promise.reject(error);
  }
);
