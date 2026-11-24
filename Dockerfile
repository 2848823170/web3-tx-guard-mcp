FROM node:22-alpine

ENV NODE_ENV="production" \
    PORT="8080"

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY .actor ./.actor
COPY bin ./bin
COPY src ./src
COPY mcpize.yaml glama.json server.json README.md LICENSE ./

RUN chown -R node:node /usr/src/app

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/index.js"]
