FROM node:22.16.0-bookworm-slim
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN chown -R node:node /app
USER node
CMD ["./node_modules/.bin/vite", "--host", "0.0.0.0"]
