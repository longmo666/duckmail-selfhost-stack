FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src
COPY public ./public

EXPOSE 8787
CMD ["npm", "start"]
