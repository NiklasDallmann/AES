cmake_minimum_required(VERSION 3.15)

project(crypto
	LANGUAGES									CXX
	VERSION										0.1.0)

find_package(OpenMP)
find_package(cxxutility REQUIRED)

set(CMAKE_CXX_STANDARD							17)
set(CMAKE_CXX_FLAGS_RELEASE						"-O3 -DNDEBUG -flto -march=native -mtune=native")
set(CMAKE_CXX_FLAGS_DEBUG						"-g")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY				"${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY				"${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY				"${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(CRYPTO_PROJECT_LOCATION						${CMAKE_CURRENT_SOURCE_DIR})

set(CRYPTO_ENABLE_TESTS							ON)

add_subdirectory("src/lib")

if (CRYPTO_ENABLE_TESTS)
	enable_testing()
	add_subdirectory("src/test/aestest")
	add_subdirectory("src/test/sha2test")
endif()

set(CRYPTO_LIBRARY_DESTINATION					"${CMAKE_INSTALL_PREFIX}/lib")
set(CRYPTO_HEADER_DESTINATION					"${CMAKE_INSTALL_PREFIX}/include/lib")
set(CRYPTO_CMAKE_DIRECTORY						"${CMAKE_INSTALL_PREFIX}/lib/cmake/crypto")

set(CRYPTO_TARGETS								${PROJECT_NAME})

# Package
set(CPACK_PACKAGE_VENDOR						"Niklas Dallmann")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY			"C++ cryptography library")
set(CPACK_PACKAGE_VERSION_MAJOR					${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR					${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH					${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE					"${CRYPTO_PROJECT_LOCATION}/LICENSE")
set(CPACK_RESOURCE_FILE_README					"${CRYPTO_PROJECT_LOCATION}/README.md")
set(CPACK_SOURCE_GENERATOR						"TGZ")
set(CPACK_SOURCE_IGNORE_FILES
	"/.git"
	"/bin"
	"/lib"
	".gitignore"
	"CMakeLists.txt.user"
	"CMakeLists.txt.autosave")

# Installation
install(TARGETS									${PROJECT_NAME}
		EXPORT									${PROJECT_NAME}
		LIBRARY
		DESTINATION								"${CRYPTO_LIBRARY_DESTINATION}")

install(FILES									${CRYPTO_PUBLIC_HEADERS}
		DESTINATION								"${CRYPTO_HEADER_DESTINATION}")

install(EXPORT									${CRYPTO_TARGETS}
		DESTINATION								${CRYPTO_CMAKE_DIRECTORY}
		FILE									"crypto-config.cmake")

include(CPack)
