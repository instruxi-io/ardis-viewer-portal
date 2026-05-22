import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: { main: 'index.html' },
    },
  },
  // Cloudflare Pages serves from / — no base path needed
});
