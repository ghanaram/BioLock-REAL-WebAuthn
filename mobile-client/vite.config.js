import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import fs from 'fs'
import path from 'path'

export default defineConfig({
  base: '/mobile/',

  plugins: [
    react(),
    tailwindcss()
  ],

  server: {
    host: '0.0.0.0',
    port: 5174,

    https: {
      key: fs.readFileSync(
        path.resolve(__dirname, '../certs/biolock.local+2-key.pem')
      ),
      cert: fs.readFileSync(
        path.resolve(__dirname, "../certs/biolock.local+2.pem")
      )
    }
  }
})