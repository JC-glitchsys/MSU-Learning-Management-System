import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite' // <-- I-import ang bagong v4 plugin
import path from 'path'

export default defineConfig({
  plugins: [
    vue(),
    tailwindcss(), // <-- Idagdag si Tailwind v4 sa build pipe ng Vite
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'), // Sinisigurong gumagana ang @ paths natin
    },
  },
})