add_library(dot1agCpp SHARED
 Dot1ag.cpp Dot1agLbm.cpp Dot1agRAps.cpp Dot1agCcm.cpp
 Runnable.cpp NetIf.cpp NetIfListener.cpp)

target_link_libraries(dot1agCpp pcap pthread)

#
# Install target
#
install (TARGETS dot1agCpp
          RUNTIME DESTINATION bin
          LIBRARY DESTINATION lib)
