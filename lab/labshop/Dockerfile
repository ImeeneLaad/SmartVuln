# LabShop - hardened image: small base, no package manager at runtime, health check.
FROM node:22-alpine

WORKDIR /app
COPY package.json package-lock.json ./
# Install production dependencies, then remove npm (only needed while building).
RUN npm ci --omit=dev --no-audit --no-fund \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm

COPY . .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD ["node", "-e", "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
