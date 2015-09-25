mod_log_gelf.la: mod_log_gelf.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_gelf.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_log_gelf.la
