set(MANPAGES nfs-cat.1
             nfs-cp.1
             nfs-ls.1)

set(DOCBOOK_URL http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl)

# Pre-generated manpages are shipped in the source tree and are what we
# install by default. ENABLE_DOCUMENTATION only asks for them to be
# regenerated from the docbook sources, which requires xsltproc and network
# access to the docbook stylesheets.
foreach(MANPAGE ${MANPAGES})
  list(APPEND MANPAGE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${MANPAGE})
endforeach()

if(ENABLE_DOCUMENTATION)
  find_program(XSLTPROC_PROGRAM xsltproc)

  if(XSLTPROC_PROGRAM)
    unset(MANPAGE_FILES)
    foreach(MANPAGE ${MANPAGES})
      add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE}
                         COMMAND ${XSLTPROC_PROGRAM} -o ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE}
                                 ${DOCBOOK_URL} ${CMAKE_CURRENT_SOURCE_DIR}/${MANPAGE}.xml
                         DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${MANPAGE}.xml
                         COMMENT "Generating ${MANPAGE}")
      list(APPEND MANPAGE_FILES ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
    endforeach()

    add_custom_target(doc ALL DEPENDS ${MANPAGE_FILES})
  else()
    message(WARNING "xsltproc not found, installing the pre-generated manpages")
  endif()
endif()

# The manpages document the utilities, so only install them when the
# utilities themselves are installed.
if(ENABLE_UTILS)
  install(FILES ${MANPAGE_FILES}
          DESTINATION ${INSTALL_MAN_DIR}/man1/)
endif()
