mod_session_header.la: mod_session_header.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_session_header.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_session_header.la
