FROM node:24-alpine
WORKDIR /app
COPY hub ./hub
COPY agent ./agent
ENV LCTL_DATA=/data LCTL_PORT=7420 NODE_ENV=production
RUN mkdir -p /data && chown node:node /data
VOLUME /data
EXPOSE 7420
USER node
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:7420/healthz || exit 1
CMD ["node", "hub/server.js"]
