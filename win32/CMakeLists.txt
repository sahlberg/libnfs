set(SOURCES win32_compat.c)
set(HEADERS ../include/win32/win32_compat.h
            win32_errnowrapper.h)

core_add_library(win32)
