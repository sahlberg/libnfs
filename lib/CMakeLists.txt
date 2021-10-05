set(SOURCES init.c
            libnfs.c
            libnfs-sync.c
            libnfs-zdr.c
            multithreading.c
            nfs_v3.c
            nfs_v4.c
            pdu.c
            socket.c
)

# deal with version info in "dll" case
if(WIN32 AND BUILD_SHARED_LIBS)
  configure_file(../win32/version.rc.template version.rc @ONLY)
  list(APPEND SOURCES ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
endif()

add_library(nfs ${SOURCES})
target_link_libraries(nfs PRIVATE ${CORE_LIBRARIES} PUBLIC ${SYSTEM_LIBRARIES})
set_target_properties(nfs PROPERTIES
                          VERSION ${PROJECT_VERSION}
                          SOVERSION ${SOVERSION})

install(TARGETS nfs EXPORT libnfs
                    RUNTIME DESTINATION bin
                    ARCHIVE DESTINATION lib
                    LIBRARY DESTINATION lib)
