cmake_minimum_required(VERSION 3.16)
project(ElfReader LANGUAGES CXX)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ElfReader SHARED
    src/ElfReader.cpp)

add_executable(ElfReaderTest  
    src/test.cpp)

target_compile_definitions(ElfReader PRIVATE ELFREADER_EXPORTS)

target_include_directories(ElfReader PUBLIC
    src
    includes
    external/ELFIO
)


target_link_libraries(ElfReaderTest PRIVATE ElfReader)
target_include_directories(ElfReaderTest PRIVATE includes)