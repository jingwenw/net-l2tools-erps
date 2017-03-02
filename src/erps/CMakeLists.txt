add_executable(erpsd erpsd.cpp ErpsEngine.cpp)
target_link_libraries(erpsd pcap dot1agCpp)

#
# Install target
#
install (TARGETS erpsd
          RUNTIME DESTINATION bin
          LIBRARY DESTINATION lib)

