# apache-mod_log_gelf
### (BETA, not tested in production environments!)
Apache2 module for writing access logs to Graylog

# Install system package
Download a package for your operating system from [here](https://github.com/Graylog2/apache-mod_log_gelf/releases)
Update Apache2 to the latests version and use `mpm_prefork`.

Ubuntu:

```
  $ sudo apt-get update
  $ sudo apt-get upgrade
  $ sudo a2enmod mpm_prefork
  $ sudo apt-get install libjson-c2 zlib1g
  $ sudo dpkg -i libapache2-mod-gelf_0.1.0-1_amd64.deb
  $ sudo a2enmod log_gelf
  restart apache
```

Older Debian systems need installed backports repository in order to install `libjson-c2`:

```
  $ echo 'deb http://http.debian.net/debian wheezy-backports main' >> /etc/apt/sources.list
  $ sudo apt-get update
  $ sudo apt-get upgrade
  $ sudo a2enmod mpm_prefork
  $ sudo apt-get install libjson-c2 zlib1g
  $ sudo dpkg -i libapache2-mod-gelf_0.1.0-1_amd64.deb
  $ sudo a2enmod log_gelf
  restart apache
```

CentOS (>= 7):

```
  $ sudo yum install json-c zlib
  $ sudo rpm -i libapache2-mod-gelf-0.1.0-1.x86_64.rpm
  restart apache
```

FreeBSD:

```
  $ pkg install gmake
  $ pkg install json-c
  $ gmake && sudo gmake install
  restart apache
```

# Configuration

Load the module in `/etc/apache2/mods-enabled/log_gelf.load`:

```
  LoadModule log_gelf_module /usr/lib/apache2/modules/mod_log_gelf.so
```

Configure the module in `/etc/apache2/mods-enabled/log_gelf.conf`:

```
  GelfEnabled On
  GelfUrl "udp://192.168.1.1:12201"
  GelfSource "hostname"
  GelfFacility "apache-gelf"
  GelfTag "gelf-tag"
  GelfCookie "tracking"
  GelfFields "ABDhmsvRti"
```
On CentOS both files are combined in `/etc/httpd/conf.modules.d/02-gelf.conf`

| Parameter    | Argument               | Description                                            |
|--------------|------------------------|--------------------------------------------------------|
| GelfEnabled  | On/Off                 | Load GELF logging module                               |
| GelfUrl      | Graylog server URL     | Set IP and port of a UDP GELF input                    |
| GelfSource   | (Optional)             | Overwrite source field                                 |
| GelfFacility | (Optional)             | Overwrite logging facility                             |
| GelfTag      | (Optional)             | Add a `tag` field to every log message                 |
| GelfCookie   | (Optional) cookie name | Extract one cookie from web request, Use 'c' GelfField |
| GelfHeader   | (Optional) header name | Extract one header from web request, Use 'X' GelfField |
| GelfFields   | (Optional)             | Configures which information should be logged          |

What does the `GelfFields` string mean:

| Character | Logging information                         |
|-----------|---------------------------------------------|
| A         | Agent string                                |
| a         | Request arguments                           |
| B         | Bytes send                                  |
| C         | Connection status                           |
| c         | Extract Cookie (name must be in GelfCookie) |
| D         | Request duration (in microseconds)          |
| f         | Requested file                              |
| H         | Protocol                                    |
| h         | Remote host                                 |
| i         | Remote address                              |
| L         | Local address                               |
| l         | Auth login name                             |
| m         | Request methode                             |
| p         | Server port                                 |
| P         | Child PID                                   |
| R         | Referer                                     |
| r         | Request string                              |
| s         | Return status                               |
| t         | Request timestamp                           |
| U         | Request URI                                 |
| u         | Username                                    |
| V         | Server name                                 |
| v         | VirtualHost name                            |
| X         | Extract Header (name must be in GelfHeader) |

# Packages

Build Docker base images:

```
  $ docker build -t apache-gelf-ubuntu dist/ubuntu1404/
  $ docker build -t apache-gelf-debian dist/debian7/
  $ docker build -t apache-gelf-centos dist/centos7/
```

Bundle module and configuration files to system package, e.g. for Ubuntu:

```
  $ docker run --rm=true -v `pwd`:/apache-gelf -t -i apache-gelf-ubuntu fpm-cook package /apache-gelf/dist/recipe.rb
```

# Compile

Install dependent c libraries:

```
  $ sudo apt-get install apache2-dev libjson-c-dev zlib1g-dev
```

Compile and install modules:

```
  $ cd src
  $ make
  $ sudo make install
```

# License

Copyright (C) 2015 Graylog, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
