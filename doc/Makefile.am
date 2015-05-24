XSLTPROC = /usr/bin/xsltproc

EXTRA_DIST = nfs-cat.1 nfs-cat.1.xml nfs-cp.1 nfs-cp.1.xml nfs-ls.1 nfs-ls.1.xml

# Manpages
man1_MANS = nfs-cat.1 nfs-cp.1 nfs-ls.1

doc:
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o nfs-cat.1 http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl nfs-cat.1.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o nfs-cp.1 http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl nfs-cp.1.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o nfs-ls.1 http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl nfs-ls.1.xml
