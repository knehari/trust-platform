import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, '.', '');
  return {
    server: {
      proxy: {
        // The API serves HTTPS in the laboratory (ADR-0032): the proxy verifies
        // its certificate (NODE_EXTRA_CA_CERTS names the lab CA).
        '/v1': { target: environment.TRUST_API_DEV_TARGET ?? 'https://127.0.0.1:8081', changeOrigin: false, secure: true },
      },
    },
  };
});
