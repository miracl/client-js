FROM node:alpine

RUN apk add --no-cache --update git

WORKDIR /home/node
