# Use Alpine for smaller footprint (approx 50MB vs 200MB+)
FROM node:20-alpine

WORKDIR /usr/src/app

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Copy the rest of the application code
COPY . .

# Ensure data directory exists
RUN mkdir -p data
VOLUME ["/usr/src/app/data"]

ENV PORT=3000
EXPOSE 3000

CMD [ "node", "server.js" ]