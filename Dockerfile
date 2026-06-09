FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY subscription-converter.js /usr/share/nginx/html/subscription-converter.js

EXPOSE 80
