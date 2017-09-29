find_library(TALLOC_LIBRARY talloc)
find_library(TALLOC_EVENT_LIBRARY tevent)
find_library(EVENT_LIBARY event)
find_library(POPT_LIBRARY popt)

list(APPEND CORE_LIBRARIES ${POPT_LIBRARY})

set(SOURCES nfsclient-async
            nfsclient-raw
            nfsclient-sync
            nfsclient-bcast
            nfsclient-listservers
            nfs-io
            nfs-ln
            portmap-client)

if(HAVE_TALLOC_TEVENT)
  list(APPEND SOURCES nfs4-cat-talloc)
  list(APPEND CORE_LIBRARIES ${TALLOC_EVENT_LIBRARY} ${TALLOC_LIBRARY})
endif()

if(EVENT_LIBARY)
  list(APPEND SOURCES nfs4-cat
                      portmap-server)
  list(APPEND CORE_LIBRARIES ${EVENT_LIBARY})
endif()

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} ${CORE_LIBRARIES})
  add_dependencies(${TARGET} nfs)
endforeach()

add_definitions("-D_U_=__attribute__((unused))")
