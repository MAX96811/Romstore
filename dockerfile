# Use an official Node.js runtime as a parent image
FROM node:20-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Bundle app source
COPY . .
 ENV PORT=3000
# Expose the port the app runs on
EXPOSE 3000

# Command to run the application
CMD [ "node", "server.js" ]
