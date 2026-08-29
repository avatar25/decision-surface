import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Rego evaluation runs against a local `opa run --server` (see README).
// Proxied so the browser can talk to it without CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/opa': {
        target: 'http://localhost:8181',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/opa/, ''),
      },
    },
  },
})
