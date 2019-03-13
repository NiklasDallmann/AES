#DEFINES					+= NO_DEBUG

QMAKE_CXXFLAGS			+= -std=c++17 -Werror=return-type
QMAKE_CXXFLAGS_RELEASE	-= -O1 -O2 -march=generic -mtune=generic
QMAKE_CXXFLAGS_RELEASE	*= -O3 -flto -s -march=native -mtune=native -funroll-all-loops -mavx2 -mmovbe -falign-functions=32 #-falign-loops=64
#QMAKE_CXXFLAGS_RELEASE	*= -O3 -flto -g -march=native -mtune=native -funroll-all-loops -mavx2 -mmovbe -falign-functions=32 #-falign-loops=64

QMAKE_CXXFLAGS			+= -fopenmp
QMAKE_LFLAGS			+= -fopenmp

LIBS					+= -fopenmp
