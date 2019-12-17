FROM node:10
WORKDIR /usr/src/app
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production
COPY . . 
EXPOSE 8081
CMD [ "node", "server.js" ]

