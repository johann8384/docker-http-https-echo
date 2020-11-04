FROM node:10-alpine

WORKDIR /app

COPY . .

ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache g++ make python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

ENV HTTP_PORT=80 HTTPS_PORT=443

ENV JAEGER_SERVICE_NAME=echo-server
ENV JAEGER_AGENT_HOST=localhost
ENV JAEGER_AGENT_PORT=6831
ENV JAEGER_AGENT_SOCKET_TYPE=udp4
ENV JAEGER_REPORTER_LOG_SPANS=true
ENV JAEGER_DISABLED=false

RUN npm install --production

RUN apk --no-cache add openssl && sh generate-cert.sh && rm -rf /var/cache/apk/*

CMD ["node", "./index.js"]
