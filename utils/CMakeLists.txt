set(UTILITIES nfs-cat nfs-ls)

if(NOT CMAKE_SYSTEM_NAME STREQUAL Windows)
  list(APPEND UTILITIES nfs-cp nfs-stat)
endif()

foreach(TARGET ${UTILITIES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs nfs_mount)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${TARGET}
          DESTINATION ${INSTALL_BIN_DIR})
endforeach()
