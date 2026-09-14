find_library(DL_LIBRARY dl)

set(TEST_PROGS prog_access
               prog_access2
               prog_chmod
               prog_chown
               prog_concurrent
               prog_create
               prog_fchmod
               prog_fchown
               prog_fstat
               prog_fallocate
               prog_ftruncate
               prog_lchmod
               prog_lchown
               prog_link
               prog_lseek
               prog_lstat
               prog_mkdir
               prog_mknod
               prog_mount
               prog_nfs4_stat
               prog_open_read
               prog_open_write
               prog_opendir
               prog_parse_url_full
               prog_read_update_pos
               prog_rename
               prog_rmdir
               prog_stat
               prog_statvfs
               prog_symlink
               prog_timeout
               prog_truncate
               prog_unlink
               prog_utimes
               prog_zdr_alignment)

foreach(TARGET ${TEST_PROGS})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs)
endforeach()

add_test(NAME zdr_alignment COMMAND prog_zdr_alignment)

add_library(ld_timeout SHARED ld_timeout.c)
set_target_properties(ld_timeout PROPERTIES PREFIX "")
target_link_libraries(ld_timeout nfs ${DL_LIBRARY})

set(UNIT_TEST_PROGS prog_nfs4_delay)

foreach(TARGET ${UNIT_TEST_PROGS})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs)
  add_test(NAME ${TARGET} COMMAND ${TARGET})
endforeach()

file(GLOB TESTS test_*.sh)

file(COPY functions.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

foreach(TEST ${TESTS})
  file(COPY ${TEST} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  add_test(NAME ${TEST}
           COMMAND ${TEST}
           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()

add_executable(prog_zdr_bytes_zero prog_zdr_bytes_zero.c)
target_link_libraries(prog_zdr_bytes_zero nfs)
add_test(NAME zdr_bytes_zero COMMAND prog_zdr_bytes_zero)
