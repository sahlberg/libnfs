XSLTPROC = /usr/bin/xsltproc

# Manpages
man1_MANS = nfs-ls.1
CLEANFILES = $(man1_MANS)

nfs-ls.1: nfs-ls.1.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
