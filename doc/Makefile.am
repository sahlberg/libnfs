XSLTPROC = /usr/bin/xsltproc

EXTRA_DIST = nfs-ls.1 nfs-ls.1.xml

# Manpages
man1_MANS = nfs-ls.1

doc:
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o nfs-ls.1 http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl nfs-ls.1.xml
