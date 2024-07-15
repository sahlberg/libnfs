find_library(TALLOC_LIBRARY talloc)
find_library(TALLOC_EVENT_LIBRARY tevent)
find_library(EVENT_LIBARY event)

set(EXTRA_LIBRARIES "")

set(EXAMPLES nfsclient-async
            nfsclient-raw
            nfsclient-sync
            nfsclient-bcast
            nfsclient-listservers
            nfs-io
            nfs-ln
            nfs-writefile
            portmap-client)

if (ENABLE_MULTITHREADING)
  list(APPEND EXAMPLES nfs-pthreads-writefile
                       nfs-pthreads-async-writefile
                       nfs-pthreads-async-readfile)
  list(APPEND EXTRA_LIBRARIES pthread)
endif()

if(HAVE_TALLOC_TEVENT)
  list(APPEND EXAMPLES nfs4-cat-talloc)
  list(APPEND EXTRA_LIBRARIES ${TALLOC_EVENT_LIBRARY} ${TALLOC_LIBRARY})
endif()

if(EVENT_LIBARY)
  list(APPEND EXAMPLES nfs4-cat
                       portmap-server)
  list(APPEND EXTRA_LIBRARIES ${EVENT_LIBARY})
endif()

include_directories(../mount
  ../nfs
  ../nfs4
  ../portmap
  ../rquota)

foreach(TARGET ${EXAMPLES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs ${EXTRA_LIBRARIES})
endforeach()
