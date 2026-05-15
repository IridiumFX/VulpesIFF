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
		src/main/c/IFF_Boundary.c
		src/main/c/IFF_ChecksumAlgorithm.c
		src/main/c/IFF_ChecksumCalculator.c
		src/main/c/IFF_ChecksumSpan.c
		src/main/c/IFF_Checksum_CRC32C.c
		src/main/c/IFF_Checksum_CRC64ECMA.c
		src/main/c/IFF_Checksum_LRC.c
		src/main/c/IFF_Checksum_RFC1071.c
		src/main/c/IFF_Chunk.c
		src/main/c/IFF_Chunk_Key.c
		src/main/c/IFF_ChunkDecoder.c
		src/main/c/IFF_ChunkEncoder.c
		src/main/c/IFF_Container.c
		src/main/c/IFF_ContextualData.c
		src/main/c/IFF_Directive_IFF_Processor.c
		src/main/c/IFF_DataPump.c
		src/main/c/IFF_DataTap.c
		src/main/c/IFF_FormDecoder.c
		src/main/c/IFF_FormEncoder.c
		src/main/c/IFF_Generator.c
		src/main/c/IFF_Generator_Factory.c
		src/main/c/IFF_Header.c
		src/main/c/IFF_Parser.c
		src/main/c/IFF_Parser_Factory.c
		src/main/c/IFF_Parser_Session.c
		src/main/c/IFF_Parser_State.c
		src/main/c/IFF_Reader.c
		src/main/c/IFF_ReaderFrame.c
		src/main/c/IFF_Scope.c
		src/main/c/IFF_Tag.c
		src/main/c/IFF_WritePump.c
		src/main/c/IFF_WriteScope.c
		src/main/c/IFF_WriteTap.c
		src/main/c/IFF_Writer.c
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
add_subdirectory(src/test/c)

# Codec demo CLI.
add_executable(VulpesIFF_CodecDemo Codecs/demo_codecs.c)
target_include_directories(VulpesIFF_CodecDemo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Codecs)
target_link_libraries(VulpesIFF_CodecDemo PRIVATE VulpesIFF m)

