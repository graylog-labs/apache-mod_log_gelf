FROM debian:wheezy

MAINTAINER Graylog Inc. <hello@graylog.com>

RUN 	echo "deb http://archive.debian.org/debian wheezy main" > /etc/apt/sources.list \
	&& echo "deb http://archive.debian.org/debian-security wheezy/updates main" >> /etc/apt/sources.list \
	&& echo "deb http://archive.debian.org/debian wheezy-backports main" > /etc/apt/sources.list.d/backports.list \
	&& apt-get update -o Acquire::Check-Valid-Until=false \
	&& apt-get install -y ruby ruby-dev build-essential curl lsb-release \
	&& apt-get install -y apache2-threaded-dev libjson-c-dev zlib1g-dev \
	&& gem install -v 1.10 ffi --no-ri --no-rdoc \
	&& gem install fpm-cookery --no-ri --no-rdoc \
	&& apt-get clean

