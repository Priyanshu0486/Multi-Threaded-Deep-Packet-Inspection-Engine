# Stage 1: Build the Java DPI engine
FROM maven:3.9-amazoncorretto-17 AS java-builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean compile

# Stage 2: Build the Next.js web application
FROM node:20-alpine AS web-builder
WORKDIR /web-ui
COPY web-ui/package.json web-ui/package-lock.json* ./
RUN npm install
COPY web-ui .
RUN npm run build

# Stage 3: Final Production Image
FROM amazoncorretto:17-alpine
WORKDIR /app

# Install Node.js in the Corretto image so we can run Next.js
RUN apk add --no-cache nodejs npm

# Copy compiled Java classes
COPY --from=java-builder /app/target /app/target

# Copy Next.js built app
WORKDIR /app/web-ui
COPY --from=web-builder /web-ui/package.json ./
COPY --from=web-builder /web-ui/node_modules ./node_modules
COPY --from=web-builder /web-ui/.next ./.next
COPY --from=web-builder /web-ui/public ./public

# Set environment variable so the API route knows it's in Docker
ENV IS_DOCKER=true
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Start the Next.js server
CMD ["npm", "start"]
