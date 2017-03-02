/*
 *     Copyright (c) 2017
 *     Author: James Wang.
 *     All rights reserved.
 *
 */

This is the ERPS simulator tool, which continually sending CFM CCM messages,
and when a failure detected (no CCMs received over 3 X interval), it will
send out R-APS SF(signal fail) message to the multicast mac address, based on
G.8032/Y.1344.

This tool is making use of libpcap and using cmake as the build tool.

To build:
  1. checkout the code repo from Gerrit with project name, packetier-erps
  2. Goto the root dir of the working dir
  3. Create a build dir, e.g., mkdir -p build
  4. Goto the build dir. e.g., cd build
  5. Run CMake: "cmake .."
  6. Build the tool by running "make"
  7. Install the tool by running "make install"
  8. Package the tool in a RPM by running "make package"

The binary tool, erpsd, is located under ./bin, and the dependant lib,
  libdot1agCpp.so, is located under ./lib

The usaage of this tool is available via the option "-h", e.g., bin/erpsd -h

The example of using this tool are as following:

  - Make sure the lib directory is in $LD_LIBRARY_PATH, e.g.:
     export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:lib

  - To run the tool as a daemon, waiting for dot1ag packets and continually
  sending CCMs:
       bin/erpsd -i ens3 -m 22

  - Run the same command with different meid, via "-m" on another host, e.g:
       bin/erpsd -i ens3 -m 23

  Then you'll see CCMs flies and R-APS sent out if failure occurs from either
  side.
