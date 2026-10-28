import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Runs on 5174 so it won't clash with the main dashboard (5173).
// Proxies API paths to the AgentBreak backend, so live fetches are
// same-origin (no CORS setup needed).
const backend = 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      '/api': { target: backend, changeOrigin: true },
      '/runs': { target: backend, changeOrigin: true },
      '/health': { target: backend, changeOrigin: true },
    },
  },
});
