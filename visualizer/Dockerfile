# Stage 1: build the React frontend
FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json ./
RUN npm install
COPY frontend/ .
# override outDir so the built assets land in a known location
RUN VITE_BASE=/visualizer/ npx vite build --outDir /frontend-dist

# Stage 2: production Node server
FROM node:20-alpine
WORKDIR /app
COPY backend/package.json ./
RUN npm install --production
COPY backend/ .
COPY --from=frontend-build /frontend-dist ./public
COPY topology.config.json .
ENV PORT=3001
ENV TOPOLOGY_CONFIG=/app/topology.config.json
EXPOSE 3001
CMD ["node", "server.js"]
