set(UTILITIES nfs-cat nfs-ls nfs-cp nfs-stat)


foreach(TARGET ${UTILITIES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs)
  target_include_directories(${TARGET} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../mount")

  

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(${TARGET} PROPERTIES
      INSTALL_RPATH "${INSTALL_LIB_DIR}"
      BUILD_RPATH "${INSTALL_LIB_DIR}"
    )
  endif()

  install(TARGETS ${TARGET}
          PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
          DESTINATION ${INSTALL_BIN_DIR})
endforeach()
