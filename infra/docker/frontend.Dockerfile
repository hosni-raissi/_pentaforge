FROM node:20-alpine AS build

WORKDIR /app

# Copy package management files
COPY client/ui/package.json client/ui/package-lock.json ./client/ui/

# Install dependencies
WORKDIR /app/client/ui
RUN npm ci

# Copy source
COPY client/ui/ ./
RUN npm run web:build

# Use nginx for serving
FROM nginx:alpine

RUN apk add --no-cache curl

# Copy built assets
COPY --from=build /app/client/ui/dist /usr/share/nginx/html
COPY infra/nginx/default.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
