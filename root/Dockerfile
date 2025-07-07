FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

USER root

EXPOSE 3000
CMD ["npm", "start"]