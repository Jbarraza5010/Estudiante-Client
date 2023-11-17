cmake_minimum_required(VERSION 3.26)
project(Client)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenCV REQUIRED)

add_executable(Client main.cpp)

include_directories(${OpenCV_INCLUDE_DIRS})

target_link_libraries(Client ${OpenCV_LIBS} ssl crypto)
