# High-Performance Node.js 20 Alpine Image
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 5001
ENV PORT=5001
ENV NODE_ENV=production

CMD ["node", "app.js"]
