cmake_minimum_required(VERSION 3.16)
project(SNESRecompilerGUI)

set(CMAKE_CXX_STANDARD 17)

# Set the path to your static Qt installation
set(Qt5_DIR "C:/Qt/Qt5.15.2/static/lib/cmake/Qt5")

find_package(Qt5 COMPONENTS Widgets REQUIRED)

add_executable(SNESRecompilerGUI main.cpp recompiler.cpp)
target_link_libraries(SNESRecompilerGUI Qt5::Widgets)
