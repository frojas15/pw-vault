import { defineConfig } from 'vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'
import { VitePWA } from 'vite-plugin-pwa'

// https://vite.dev/config/
export default defineConfig({
  base: '/pw-vault/',
  plugins: [
    react(),
    babel({ presets: [reactCompilerPreset()] }),
    VitePWA({
      registerType: 'autoUpdate',
      manifest: {
        name: 'Password Vault',
        short_name: 'Vault',
        description: 'Encrypted local password vault',
        theme_color: '#0d80c6',
        background_color: '#f5f8ff',
        display: 'standalone',
        scope: '/pw-vault/',
        start_url: '/pw-vault/',
        icons: [
          { src: '/pw-vault/icons.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,png,woff2}'],
      },
    }),
  ],
})
