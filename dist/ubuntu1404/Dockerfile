FROM ubuntu:14.04

MAINTAINER Graylog Inc. <hello@graylog.com>

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y ruby1.9.1 ruby1.9.1-dev build-essential curl lsb-release
RUN apt-get install -y autoconf apache2-dev libjson-c-dev
RUN gem install fpm-cookery --no-ri --no-rdoc

# Remove cached packages and metadata to keep images small.
RUN apt-get clean
