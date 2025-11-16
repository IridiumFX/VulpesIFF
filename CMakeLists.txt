cmake_minimum_required(VERSION 3.22)
project(VulpesIFF VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Dependency Management ---
# We use Git submodules for dependencies. VulpesCore is expected to be
# in the 'dependencies' directory. This makes its targets available.
add_subdirectory(dependencies/VulpesCore)

# Define the 'VulpesIFF' library target.
add_library(VulpesIFF STATIC)

# Add the source files for this library.
target_sources(VulpesIFF PRIVATE
		src/IFF_Parser.c
		src/IFF_Parser_State.c
		src/IFF_Header.c
		src/IFF_CheckedReader.c
		src/IFF_Chunk.c
		src/IFF_Chunk_Key.c
		src/IFF_ChunkDecoder.c
		src/IFF_ContextualData.c
		src/IFF_ControlledReader.c
		src/IFF_FormDecoder.c
		src/IFF_Reader.c
		src/IFF_Scope_State.c
		src/IFF_Container.c
		src/IFF_Tag.c
)

# Define the public include directory.
target_include_directories(VulpesIFF PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:include>
)

# Link this module to its dependencies.
target_link_libraries(VulpesIFF PUBLIC VulpesCore)

# Add the test subdirectory to the build.
add_subdirectory(Tests)
