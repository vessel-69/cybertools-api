import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const API_ROUTES = [
  '/recon', '/analyze-url', '/bb-scan', '/payloads',
  '/workflow', '/workflows', '/last-scan', '/chat-assist',
  '/hash', '/encode', '/decode', '/password', '/ip', '/time', '/docs',
  '/api', '/expand', '/endpoints', '/params',
]

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      API_ROUTES.map(route => [route, { target: 'http://localhost:8000', changeOrigin: true }])
    ),
  },
  build: {
    outDir: '../frontend/dist',
    emptyOutDir: true,
  },
})