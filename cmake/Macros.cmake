# Add sources to main application
# Arguments:
#   name name of the library to add
# Implicit arguments:
#   SOURCES the sources of the library
#   HEADERS the headers of the library (only for IDE support)
# On return:
#   Library will be built and added to ${CORE_LIBRARIES}
function(core_add_library name)
  set(name nfs_${name})
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  add_library(${name} OBJECT ${SOURCES} ${HEADERS})
  target_include_directories(${name} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
  target_include_directories(${name} PRIVATE ${INCLUDEDIRS})
  set(CORE_LIBRARIES "${name};${CORE_LIBRARIES}" CACHE INTERNAL "")

  # no need to install core libs if we build shared library
  if(NOT BUILD_SHARED_LIBS)
    install(TARGETS ${name} EXPORT libnfs
            RUNTIME DESTINATION bin
            ARCHIVE DESTINATION lib
            LIBRARY DESTINATION lib)
  endif()
endfunction()
