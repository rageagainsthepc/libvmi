cmake_policy(SET CMP0079 NEW)

find_file(LIBMICROVMI_H libmicrovmi.h)

if(NOT LIBMICROVMI_H)
    message(SEND_ERROR "Cannot find libmicrovmi.h")
else()
    message("Libmicrovmi header path: ${LIBMICROVMI_H}")
    get_filename_component(LIBMICROVMI_INCLUDE_DIR ${LIBMICROVMI_H} DIRECTORY)
    target_include_directories(vmi_shared PRIVATE ${LIBMICROVMI_INCLUDE_DIR})
    target_include_directories(vmi_static PRIVATE ${LIBMICROVMI_INCLUDE_DIR})
endif()

find_library(LIBMICROVMI libmicrovmi.so)

if (NOT LIBMICROVMI)
    message(SEND_ERROR "Unable to locate libmicrovmi")
else()
    message("Libmicrovmi library path: ${LIBMICROVMI}")
    target_link_libraries(vmi_shared PRIVATE ${LIBMICROVMI})
    target_link_libraries(vmi_static PRIVATE ${LIBMICROVMI})
endif()
