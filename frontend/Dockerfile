FROM node:22-alpine AS build
WORKDIR /src
COPY package.json .
RUN npm install
COPY . .
RUN npm run build
FROM nginx:alpine
COPY --from=build /src/dist /usr/share/nginx/html
