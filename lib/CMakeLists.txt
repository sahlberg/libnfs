add_library(nfs init.c
                libnfs.c
                libnfs-sync.c
                libnfs-zdr.c
                nfs_v3.c
                nfs_v4.c
                pdu.c
                socket.c)

target_include_directories(nfs PUBLIC ../include)
target_link_libraries(nfs PUBLIC ${CORE_LIBRARIES} ${SYSTEM_LIBRARIES})
set_target_properties(nfs PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          SOVERSION ${SOVERSION})

install(TARGETS nfs EXPORT nfs
                    RUNTIME DESTINATION bin
                    ARCHIVE DESTINATION lib
                    LIBRARY DESTINATION lib)
