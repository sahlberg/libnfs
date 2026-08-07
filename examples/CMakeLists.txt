find_library(TALLOC_LIBRARY talloc)
find_library(TALLOC_EVENT_LIBRARY tevent)
find_library(EVENT_LIBARY event)

set(EXTRA_LIBRARIES "")

set(EXAMPLES nfsclient-async
            nfsclient-raw
            nfsclient-sync
            nfsclient-bcast
            nfsclient-listservers
            nfs-cat-preadv
            nfs-fh
            nfs-io
            nfs-ln
            nfs-writefile
	    nfs-nfsstat
	    nfs-stats-cb
            portmap-client)

if (ENABLE_MULTITHREADING)
  list(APPEND EXAMPLES nfs-pthreads-example
                       nfs-pthreads-fstat
                       nfs-pthreads-writefile
                       nfs-pthreads-async-writefile
                       nfs-pthreads-async-readfile)
endif()

if(HAVE_TALLOC_TEVENT)
  list(APPEND EXAMPLES nfs4-cat-talloc)
  list(APPEND EXTRA_LIBRARIES ${TALLOC_EVENT_LIBRARY} ${TALLOC_LIBRARY})
endif()

if(EVENT_LIBARY)
  # rpcbind moved to servers/rpcbind in f63eaca8 and is built from there.
  list(APPEND EXAMPLES nfs4-cat)
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
