FROM nginx:1.27-alpine

# Static frontend
COPY frontend/ /usr/share/nginx/html/
# Reverse proxy: /api/* -> backend
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
