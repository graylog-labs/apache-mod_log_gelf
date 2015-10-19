FROM debian:wheezy

MAINTAINER Graylog Inc. <hello@graylog.com>

RUN echo 'deb http://http.debian.net/debian wheezy-backports main' >> /etc/apt/sources.list
RUN apt-get clean
RUN apt-get update
RUN apt-get install -y ruby1.9.1 ruby1.9.1-dev build-essential curl lsb-release
RUN apt-get install -y apache2-threaded-dev libjson-c-dev zlib1g-dev
RUN gem install fpm-cookery --no-ri --no-rdoc

# Remove cached packages and metadata to keep images small.
RUN apt-get clean
