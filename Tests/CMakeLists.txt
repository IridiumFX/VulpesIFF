cmake_minimum_required(VERSION 3.10)

project(VulpesIFF_Tests)

# Define the test executable
add_executable(ilbm_info
    ilbm_info/main.c
    ilbm_info/ilbm_decoders.c
)

# Include the IFF library's include directory and the test directory itself
target_include_directories(ilbm_info PRIVATE
    ../include
    ilbm_info
)

# Link the test executable against the main IFF library
target_link_libraries(ilbm_info PRIVATE VulpesIFF)

# Optional: Add this directory to the main project's build
# This would typically be done in the parent CMakeLists.txt with:
# add_subdirectory(Tests)
