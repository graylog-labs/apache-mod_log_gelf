# apache-mod_log_gelf
Apache2 module for writing access logs to Graylog

# Install system package

Ubuntu:

```
  $ sudo apt-get install apache2 libjson-c2 zlib1g
  $ sudo dpkg -i libapache2-mod-gelf_0.1.0-1_amd64.deb
  $ sudo sudo a2enmod log_gelf
```

# Build

Install dependent c libraries:

```
  $ sudo apt-get install apache2-dev
  $ sudo apt-get install libjson-c-dev
  $ sudo apt-get install zlib1g-dev
```

Compile and install modules:

```
  $ cd src
  $ make
  $ sudo make install
```

# Configuration

Load the module `/etc/apache2/mods-enabled/log_gelf.load`:

```
  LoadModule log_gelf_module /usr/lib/apache2/modules/mod_log_gelf.so
```

Configure the module `/etc/apache2/mods-enabled/log_gelf.conf`:

```
  GelfEnabled On
  GelfUrl "udp://192.168.1.1:12201"
  GelfSource "hostname"
  GelfFacility "apache-gelf"
  GelfTag "gelf-tag"
  GelfCookie "tracking"
  GelfFields "ABDhmsvRti"
```

| Parameter    | Argument               | Description                                   |
|--------------|------------------------|-----------------------------------------------|
| GelfEnabled  | On/Off                 | Load GELF logging module                      |
| GelfUrl      | Graylog server URL     | Set IP and port of a UDP GELF input           |
| GelfSource   | (Optional)             | Overwrite source field                        |
| GelfFacility | (Optional)             | Overwrite logging facility                    |
| GelfTag      | (Optional)             | Add a `tag` field to every log message        |
| GelfCookie   | (Optional) cookie name | Extract cookie from web request               |
| GelfFields   | (Optional)             | Configures which information should be logged |

What does the `GelfFields` string mean:

| Character | Logging information |
|-----------|---------------------|
| A         | Agent string        |
| a         | Request arguments   |
| B         | Bytes send          |
| C         | Conection Status    |
| c         | Extract Cookie      |
| D         | Request duration    |
| f         | Requested file      |
| H         | Protocol            |
| h         | Remote host         |
| i         | Remote address      |
| L         | Local address       |
| l         | Auth login name     |
| m         | Request methode     |
| p         | Server posrt        |
| R         | Referer             |
| r         | Request string      |
| s         | Return status       |
| t         | Request timestamp   |
| U         | Request URI         |
| u         | Username            |
| V         | Server name         |
| v         | VirtualHost name    |

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
