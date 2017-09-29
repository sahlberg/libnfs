list(APPEND CORE_LIBRARIES ${SOCKET_LIBRARY})

set(SOURCES nfs-cat
            nfs-ls)

if(NOT CMAKE_SYSTEM_NAME STREQUAL Windows)
  list(APPEND SOURCES nfs-cp)
endif()

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} ${CORE_LIBRARIES})
  add_dependencies(${TARGET} nfs)
endforeach()

add_definitions("-D_U_=__attribute__((unused))")
