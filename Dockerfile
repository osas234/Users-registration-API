#Use Node.js LTS version
FROM node:16

#Set working directory
WORKDIR /app

#Copy package.json and install dependencies
COPY package*.json ./
RUN npm install

#Copy the rest of the application
COPY . .

#Expose the application port
EXPOSE 8080

#Start the application
CMD ["npm", "start"]