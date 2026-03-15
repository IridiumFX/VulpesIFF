cmake_minimum_required(VERSION 3.22)
project(VulpesIFF VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Dependency Management ---
# When built standalone, VulpesCore comes from the dependencies submodule.
# When built as part of the Vulpes engine, VulpesCore is already defined.
if(NOT TARGET VulpesCore)
    add_subdirectory(dependencies/VulpesCore)
endif()

# Define the 'VulpesIFF' library target.
add_library(VulpesIFF STATIC)

# Add the source files for this library.
target_sources(VulpesIFF PRIVATE
		src/IFF_Boundary.c
		src/IFF_ChecksumAlgorithm.c
		src/IFF_ChecksumCalculator.c
		src/IFF_ChecksumSpan.c
		src/IFF_Checksum_CRC32C.c
		src/IFF_Checksum_CRC64ECMA.c
		src/IFF_Checksum_LRC.c
		src/IFF_Checksum_RFC1071.c
		src/IFF_Chunk.c
		src/IFF_Chunk_Key.c
		src/IFF_ChunkDecoder.c
		src/IFF_ChunkEncoder.c
		src/IFF_Container.c
		src/IFF_ContextualData.c
		src/IFF_Directive_IFF_Processor.c
		src/IFF_DataPump.c
		src/IFF_DataTap.c
		src/IFF_FormDecoder.c
		src/IFF_FormEncoder.c
		src/IFF_Generator.c
		src/IFF_Generator_Factory.c
		src/IFF_Header.c
		src/IFF_Parser.c
		src/IFF_Parser_Factory.c
		src/IFF_Parser_Session.c
		src/IFF_Parser_State.c
		src/IFF_Reader.c
		src/IFF_ReaderFrame.c
		src/IFF_Scope.c
		src/IFF_Tag.c
		src/IFF_WritePump.c
		src/IFF_WriteScope.c
		src/IFF_WriteTap.c
		src/IFF_Writer.c
		Codecs/ILBM/ILBM_Decompression.c
		Codecs/ILBM/ILBM_Conversion.c
		Codecs/ILBM/ILBM_Codec.c
		Codecs/ILBM/ILBM_Loader.c
		Codecs/SVX8/SVX8_Decompression.c
		Codecs/SVX8/SVX8_Codec.c
		Codecs/SVX8/SVX8_Loader.c
)

# Define the public include directory.
target_include_directories(VulpesIFF PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Codecs>
		$<INSTALL_INTERFACE:include>
)

# Link this module to its dependencies.
# Link this module to its dependencies.
target_link_libraries(VulpesIFF PUBLIC VulpesCore)

# Add the test subdirectory to the build.
add_subdirectory(Tests)

