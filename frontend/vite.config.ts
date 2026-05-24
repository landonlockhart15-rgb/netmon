import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'
import fs from 'fs'

// Vite hashes bundle filenames, so each build leaves the previous ones behind.
// emptyOutDir can't help here because outDir is ../static, which also holds
// index.html, app.js, favicons, etc. This plugin clears ONLY ../static/assets
// before a build so stale bundles never accumulate.
function cleanAssetsDir() {
  return {
    name: 'clean-static-assets',
    apply: 'build' as const,
    buildStart() {
      const assetsDir = path.resolve(__dirname, '../static/assets')
      fs.rmSync(assetsDir, { recursive: true, force: true })
    },
  }
}

export default defineConfig({
  plugins: [
    cleanAssetsDir(),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: '../static',
    emptyOutDir: false,
    assetsDir: 'assets',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
    },
  },
})
