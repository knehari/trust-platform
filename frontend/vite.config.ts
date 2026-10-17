import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8081', changeOrigin: false },
    },
  },
});
