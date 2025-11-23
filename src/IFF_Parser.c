#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_DataReader.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_ScopedDictionary.h>

#include <IFF/IFF.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Chunk.h>
#include <IFF/IFF_DataPump.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser.h>

#include "IFF/IFF_Reader.h"

char IFF_Parser_Allocate
(
	struct IFF_Parser **item
)
{
	struct IFF_Parser *parser;

	if (!item)
	{
		return 0;
	}

	parser = calloc
	(
		1,
		sizeof(struct IFF_Parser)
	);
	if (!parser)
	{
		*item = 0;

		return 0;
	}

	IFF_Parser_Session_Allocate
	(
		&parser->session
	);
	if (!parser->session)
	{
		goto cleanup;
	}

	IFF_Reader_Allocate
	(
		&parser->reader
	);
	if (!parser->reader)
	{
		goto cleanup;
	}

	*item = parser;

	return 1;

cleanup:

	*item = 0;

	IFF_Parser_Release
	(
		parser
	);

	return 0;
}

char IFF_Parser_Construct
(
	struct IFF_Parser *item,
	struct VPS_Dictionary *form_decoders,
	struct VPS_Dictionary *chunk_decoders,
	struct VPS_Dictionary *directive_processors,
	int file_handle
)
{
	char result;

	if (!item || !item->reader || !item->session)
	{
		return 0;
	}

	result = IFF_Parser_Session_Construct
	(
		item->session,
		IFF_HEADER_FLAGS_1985
	);
	if (!result)
	{
		return 0;
	}

	result = IFF_Reader_Construct
	(
		item->reader,
		file_handle
	);
	if (!result)
	{
		return 0;
	}

	item->form_decoders = form_decoders;
	item->chunk_decoders = chunk_decoders;
	item->directive_processors = directive_processors;

	return 1;
}

char IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
)
{
	if (!item)
	{
		return 0;
	}

	IFF_Parser_Session_Deconstruct
	(
		item->session
	);

	IFF_Reader_Deconstruct
	(
		item->reader
	);

	item->form_decoders = 0;
	item->chunk_decoders = 0;
	item->directive_processors = 0;

	// NOTE: This is platform specific. Need a better abstraction
	item->file_handle = -1;

	return 1;
}

char IFF_Parser_Release
(
	struct IFF_Parser *item
)
{
	if (!item)
	{
		return 0;
	}

	IFF_Parser_Deconstruct
	(
		item
	);

	IFF_Parser_Session_Release
	(
		item->session
	);

	IFF_Reader_Release
	(
		item->reader
	);

	free
	(
		item
	);

	return 1;
}

char IFF_Parser_Scan
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session;
	struct IFF_Tag first_tag;
	union IFF_Header_Flags* current_flags;

	if (!parser || !parser->session || !parser->reader)
	{
		return 0;
	}

	session = parser->session;

	// --- Bootstrap Logic ---
	 current_flags = &session->active_header_flags;

	// 1. Read the very first tag from the stream using the default IFF-85 flags.
	if (!IFF_Reader_ReadTag(parser->reader, current_flags->as_fields.tag_sizing, &first_tag))
	{
		// Empty file is not an error, just nothing to do.
		session->final_entity = 0;
		return 1;
	}

	VPS_TYPE_16S ordering;
	IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_IFF, &ordering);

	if (ordering == 0)
	{
		// --- Case 1: File starts with an ' IFF' directive. ---
		struct IFF_Chunk* iff_chunk = 0;

		// Read the rest of the ' IFF' chunk (size and data).
		if (!IFF_Reader_ReadChunk(parser->reader, &current_flags->as_fields, &first_tag, &iff_chunk))
		{
			return 0; // Malformed file.
		}

		// TODO: Find and execute the ' IFF' directive processor.
		// The processor will parse the chunk data and return a command
		// to update the session's flags.

		// For now, we just release the chunk.
		IFF_Chunk_Release(iff_chunk);

		// TODO: After processing the directive, we would start the main
		// recursive scan on the *next* chunk.
		// return IFF_Parser_PRIVATE_ScanScope(parser);
	}
	else
	{
		// --- Case 2: File does NOT start with ' IFF'. ---
		// Per spec, it's a classic IFF-85 file. The default flags are correct.
		// The tag we just read is the start of the first container.

		// We must now read the rest of this first chunk.
		struct IFF_Chunk* first_container_chunk = 0;
		if (!IFF_Reader_ReadChunk(parser->reader, &current_flags->as_fields, &first_tag, &first_container_chunk))
		{
			return 0; // Malformed file.
		}

		// TODO: Process this first container chunk. This will involve:
		// 1. Checking if it's a valid container (FORM, LIST, CAT).
		// 2. Entering a new scope for this container.
		// 3. Calling the main recursive scan to process its contents.
		// 4. Leaving the scope.

		// For now, we just release the chunk.
		IFF_Chunk_Release(first_container_chunk);
	}

	return 1;
}
