# AMAS sandbox images. Built automatically by the app (docker build --target <name>),
# or manually:  docker build --target base -t amas-base docker/
#
# Each image only adds strace, which the analyzer uses to record system calls.

FROM alpine:3.20 AS base
RUN apk add --no-cache strace \
 && adduser -D -u 10001 sandbox
WORKDIR /tmp

FROM python:3.12-alpine AS python
RUN apk add --no-cache strace \
 && adduser -D -u 10001 sandbox
WORKDIR /tmp

FROM node:22-alpine AS node
RUN apk add --no-cache strace \
 && (id 10001 >/dev/null 2>&1 || adduser -D -u 10001 sandbox)
WORKDIR /tmp
