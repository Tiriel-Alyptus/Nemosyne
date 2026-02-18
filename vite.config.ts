import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import basicSsl from '@vitejs/plugin-basic-ssl'
import fs from 'fs'
import path from 'path'

// https://vite.dev/config/
function resolveHttpsOptions() {
  const keyPath = process.env.VITE_HTTPS_KEY_PATH
  const certPath = process.env.VITE_HTTPS_CERT_PATH
  if (!keyPath || !certPath) {
    return {}
  }

  const keyFile = path.resolve(keyPath)
  const certFile = path.resolve(certPath)
  if (!fs.existsSync(keyFile) || !fs.existsSync(certFile)) {
    return {}
  }

  return {
    key: fs.readFileSync(keyFile),
    cert: fs.readFileSync(certFile),
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), basicSsl()],
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    https: resolveHttpsOptions(),
    proxy: {
      '/api': 'http://localhost:8787',
    },
  },
})
