find_program(XSLTPROC_PROGRAM xsltproc)

set(MANPAGES nfs-cat.1
             nfs-cp.1
             nfs-ls.1)

set(DOCKBOOK_URL http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl)

if(XSLTPROC_PROGRAM)
  foreach(TARGET ${MANPAGES})
    file(COPY ${TARGET}.xml
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(OUTPUT ${TARGET}
                       COMMAND ${XSLTPROC_PROGRAM} -o ${TARGET} ${DOCKBOOK_URL} ${TARGET}.xml)
  endforeach()

  add_custom_target(doc ALL DEPENDS ${MANPAGES})
endif()

install(FILES ${MANPAGES}
        DESTINATION ${INSTALL_MAN_DIR}/man1/)
