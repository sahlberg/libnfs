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
  set(CORE_LIBRARIES "${name};${CORE_LIBRARIES}" CACHE INTERNAL "")
endfunction()
