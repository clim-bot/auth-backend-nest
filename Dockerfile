# Use the official Node.js image.
FROM node:14

# Set the working directory.
WORKDIR /usr/src/app

# Install app dependencies.
COPY package*.json ./
RUN npm install

# Copy the app files.
COPY . .

# Build the NestJS application.
RUN npm run build

# Expose the port the app runs on.
EXPOSE 3000

# Run the app.
CMD ["npm", "run", "start:prod"]
