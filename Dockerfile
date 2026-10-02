# High-Performance Node.js 20 Alpine Image with FFmpeg
FROM node:20-alpine

WORKDIR /app

# Install FFmpeg for real-time MP4 zero-transcode remuxing
RUN apk add --no-cache ffmpeg ca-certificates tzdata

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 5001
ENV PORT=5001
ENV NODE_ENV=production

CMD ["node", "app.js"]
