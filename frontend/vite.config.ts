import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, '.', '');
  return {
    server: {
      proxy: {
        '/v1': { target: environment.TRUST_API_DEV_TARGET ?? 'http://127.0.0.1:8081', changeOrigin: false },
      },
    },
  };
});
