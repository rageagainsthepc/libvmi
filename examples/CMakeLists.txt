set(EXTRA_LINK_LIBRARIES vmi_shared ${EXTRA_LINK_LIBRARIES})

add_executable(map-addr map-addr.c)
target_link_libraries(map-addr ${EXTRA_LINK_LIBRARIES})

add_executable(map-symbol map-symbol.c)
target_link_libraries(map-symbol ${EXTRA_LINK_LIBRARIES})

add_executable(va-pages va-pages.c)
target_link_libraries(va-pages ${EXTRA_LINK_LIBRARIES})

add_executable(event-example event-example.c)
target_link_libraries(event-example ${EXTRA_LINK_LIBRARIES})

add_executable(interrupt-event-example interrupt-event-example.c)
target_link_libraries(interrupt-event-example ${EXTRA_LINK_LIBRARIES})

add_executable(breakpoint-emulate-example breakpoint-emulate-example.c)
target_link_libraries(breakpoint-emulate-example ${EXTRA_LINK_LIBRARIES})

add_executable(wait-for-domain-example wait-for-domain-example.c)
target_link_libraries(wait-for-domain-example ${EXTRA_LINK_LIBRARIES})

add_executable(msr-event-example msr-event-example.c)
target_link_libraries(msr-event-example ${EXTRA_LINK_LIBRARIES})

add_executable(singlestep-event-example singlestep-event-example.c)
target_link_libraries(singlestep-event-example ${EXTRA_LINK_LIBRARIES})

add_executable(step-event-example step-event-example.c)
target_link_libraries(step-event-example ${EXTRA_LINK_LIBRARIES})

add_executable(xen-emulate-reponse xen-emulate-response.c)
target_link_libraries(xen-emulate-reponse ${EXTRA_LINK_LIBRARIES})

add_executable(vmi-process-list process-list.c)
target_link_libraries(vmi-process-list ${EXTRA_LINK_LIBRARIES})

add_executable(vmi-dump-memory dump-memory.c)
target_link_libraries(vmi-dump-memory ${EXTRA_LINK_LIBRARIES})

add_executable(vmi-module-list module-list.c)
target_link_libraries(vmi-module-list ${EXTRA_LINK_LIBRARIES})

if (ENABLE_WINDOWS)
    add_executable(vmi-win-guid win-guid.c)
    target_link_libraries(vmi-win-guid ${EXTRA_LINK_LIBRARIES})

    add_executable(vmi-win-offsets win-offsets.c)
    target_link_libraries(vmi-win-offsets ${EXTRA_LINK_LIBRARIES})
endif ()

install(TARGETS
    vmi-process-list
    vmi-module-list
    vmi-dump-memory
    DESTINATION bin)

if (ENABLE_WINDOWS)
    install(TARGETS
        vmi-win-guid
        vmi-win-offsets
        DESTINATION bin)
endif ()
