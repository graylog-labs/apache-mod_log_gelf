builddir=.

#   the used tools
APXS=apxs
APACHECTL=apachectl

top_builddir=$(shell $(APXS) -q exp_libexecdir)
top_srcdir=$(top_builddir)
include $(top_builddir)/build/special.mk

ifneq (,$(wildcard /etc/debian_version))
  DISTRIBUTION := $(shell lsb_release -i | cut -f2)
  RELEASE := $(shell lsb_release --short --codename)
  ifeq ($(DISTRIBUTION),Debian)
    ifeq ($(RELEASE),wheezy)
      DEFS=-DWITH_APACHE22
    endif
  endif
endif

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

