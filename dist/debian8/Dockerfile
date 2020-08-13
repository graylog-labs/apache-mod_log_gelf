FROM debian:jessie

MAINTAINER Graylog Inc. <hello@graylog.com>

RUN	apt-get update \
	&& apt-get install -y ruby ruby-dev build-essential curl lsb-release \
	&& apt-get install -y apache2-threaded-dev libjson-c-dev zlib1g-dev \
	&& gem install facter --no-ri --no-rdoc \
	&& gem install fpm-cookery --no-ri --no-rdoc \
	&& apt-get clean

