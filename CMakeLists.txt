cmake_minimum_required(VERSION 3.15)

project(crypto LANGUAGES CXX)

find_package(OpenMP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -flto -march=native -mtune=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

add_library(${PROJECT_NAME} STATIC
	"include/lib/aesblock.h"
	"include/lib/aesconstants.h"
	"include/lib/aestraits.h"
	"include/lib/cbcmode.h"
	"include/lib/cipherkey.h"
	"include/lib/ciphermode.h"
	"include/lib/cryptoglobals.h"
	"include/lib/cryptoutilities.h"
	"include/lib/ctrmode.h"
	"include/lib/paddingtype.h"
	"include/lib/sha2constants.h"
	"src/lib/sha2digest.cpp"
	"include/lib/sha2digest.h"
	"include/lib/sha2traits.h")
target_include_directories(${PROJECT_NAME}
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/lib>
)
target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX)

add_executable(aestest
	"src/test/aestest/main.cpp")
target_include_directories(aestest
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/lib>
)
target_link_libraries(aestest ${PROJECT_NAME} OpenMP::OpenMP_CXX)

add_executable(sha2test
	"src/test/sha2test/main.cpp")
target_include_directories(sha2test
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/lib>
)
target_link_libraries(sha2test ${PROJECT_NAME} OpenMP::OpenMP_CXX)
