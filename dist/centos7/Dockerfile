FROM centos:centos7

MAINTAINER Graylog Inc. <hello@graylog.com>

RUN yum clean all
RUN yum install -y rubygems ruby-devel make gcc tar rpm-build curl
RUN yum install -y httpd httpd-devel json-c-devel zlib-devel
RUN gem install fpm-cookery --no-ri --no-rdoc

# Remove cached packages and metadata to keep images small.
RUN yum clean all
