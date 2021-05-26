builddir=.

ifneq (,$(wildcard /usr/share/apache2/build/special.mk))
  top_srcdir=/usr/share/apache2
  top_builddir=/usr/share/apache2
  include /usr/share/apache2/build/special.mk
endif
# apache2.4 on freebsd
ifneq (,$(wildcard /usr/local/share/apache24/build/special.mk))
  top_srcdir=/usr/local/share/apache24
  top_builddir=/usr/local/share/apache24
  include /usr/local/share/apache24/build/special.mk
endif
ifneq (,$(wildcard /usr/lib64/httpd/build/special.mk))
  top_srcdir=/etc/httpd
  top_builddir=/usr/lib64/httpd
  include /usr/lib64/httpd/build/special.mk
endif
ifneq (,$(wildcard /etc/debian_version))
  DISTRIBUTION := $(shell lsb_release -i | cut -f2)
  RELEASE := $(shell lsb_release --short --codename)
  ifeq ($(DISTRIBUTION),Debian)
    ifeq ($(RELEASE),wheezy)
      DEFS=-DWITH_APACHE22
    endif
  endif
endif

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
LIBS=-ljson-c -lz

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_log_gelf.o mod_log_gelf.lo mod_log_gelf.slo mod_log_gelf.la 

#   simple test
test: reload
	lynx -mime_header http://localhost

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

