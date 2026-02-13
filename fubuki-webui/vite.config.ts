import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    outDir: 'dist/fubuki-webui',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/info': { target: 'http://127.0.0.1:3030', changeOrigin: true },
      '/type': { target: 'http://127.0.0.1:3030', changeOrigin: true },
    },
  },
});
