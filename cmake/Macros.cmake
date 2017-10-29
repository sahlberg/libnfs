# Add sources to main application
# Arguments:
#   name name of the library to add
# Implicit arguments:
#   SOURCES the sources of the library
#   HEADERS the headers of the library (only for IDE support)
# On return:
#   Library will be built and added to ${core_DEPENDS}
function(core_add_library name)
  set(name core_${name})
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  add_library(${name} STATIC ${SOURCES} ${HEADERS})
  target_include_directories(${name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  set(core_DEPENDS ${name} ${core_DEPENDS} CACHE STRING "" FORCE)
endfunction()
