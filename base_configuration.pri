#DEFINES					+= NO_DEBUG

QMAKE_CXXFLAGS			+= -std=c++17 -Werror=return-type
QMAKE_CXXFLAGS_RELEASE	-= -O1 -O2 -march=generic -mtune=generic
QMAKE_CXXFLAGS_RELEASE	*= -O3 -flto -s  -march=native -mtune=native -funroll-all-loops
