ARG NODE_VERSION=22

FROM node:22-slim
WORKDIR /usr/src/app
COPY . .
RUN npm ci
EXPOSE 80
CMD ["node", "index.js", "80"]