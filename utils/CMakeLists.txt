set(UTILITIES nfs-cat nfs-ls)

if(NOT CMAKE_SYSTEM_NAME STREQUAL Windows)
  list(APPEND UTILITIES nfs-cp nfs-stat)
endif()

foreach(TARGET ${UTILITIES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs nfs_mount)

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(${TARGET} PROPERTIES
      INSTALL_RPATH "${INSTALL_LIB_DIR}"
      BUILD_RPATH "${INSTALL_LIB_DIR}"
    )
  endif()

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${TARGET}
          DESTINATION ${INSTALL_BIN_DIR})
endforeach()
