#!/bin/bash
echo "Cleaning C/C++ build artifacts..."
(cd mypycxazr/lib-rt; make clean)
(cd mypycxazr/external/googletest/make; make clean)
