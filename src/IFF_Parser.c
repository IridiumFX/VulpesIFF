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
#include <IFF/IFF_Boundary.h>
#include <IFF/IFF_Scope.h>
#include <IFF/IFF_DirectiveResult.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Reader.h>

/**
 * @brief The private, iterative core of the IFF parser engine.
 * @details This function implements a stack-based state machine. It loops,
 *          reading chunks one by one and processing them within the boundaries
 *          of the current scope (the top of the session's scope_stack).
 */
static char IFF_Parser_PRIVATE_ScanScope
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session = parser->session;
	struct IFF_Scope* current_scope;
	char result = 1;

	// The main data-driven parsing loop.
	while (result)
	{
		struct IFF_Tag current_tag;
		struct IFF_Chunk* current_chunk = 0;

		// 1. Get the current scope and check for boundary conditions.
		current_scope = session->scope_stack->head->data;
		if (current_scope->boundary.bounded && current_scope->boundary.limit > 0 && current_scope->boundary.level >= current_scope->boundary.limit)
		{
			break; // Reached the end of a sized container.
		}

		// 2. Read the next tag. This is the parser's main decision point.
		if (!IFF_Reader_ReadTag(parser->reader, current_scope->flags.as_fields.tag_sizing, &current_tag))
		{
			break; // End of stream or read error.
		}
		current_scope->boundary.level += IFF_Header_Flags_GetTagLength(current_scope->flags.as_fields.tag_sizing);

		// 3. Based on the tag, read the rest of the chunk.
		if (!IFF_Reader_ReadChunk(parser->reader, &current_scope->flags.as_fields, &current_tag, &current_chunk))
		{
			result = 0; // Malformed chunk, halt parsing.
			break;
		}
		current_scope->boundary.level += IFF_Header_Flags_GetSizeLength(current_scope->flags.as_fields.sizing);
		current_scope->boundary.level += current_chunk->size;

		// 4. Dispatch the complete chunk for processing.
		if (current_chunk->tag.type == IFF_TAG_TYPE_DIRECTIVE)
		{
			// TODO: Handle directive chunk
		}
		else // It's a data tag (FORM, LIST, CAT, PROP, or a data property)
		{
			// TODO: Handle container or data chunk
		}

		// 5. Handle optional padding byte for the chunk we just processed.
		if ((current_chunk->size % 2 != 0) && !(current_scope->flags.as_fields.structuring & IFF_Header_Flag_Structuring_NO_PADDING))
		{
			if (!IFF_Reader_Skip(parser->reader, 1))
			{
				result = 0;
				break;
			}
			current_scope->boundary.level++;
		}

		// We are done with the chunk for this iteration.
		IFF_Chunk_Release(current_chunk);
	}

	// If we exit the loop, it means we hit EOF or a container boundary.
	// TODO: Finalize any active chunk/form decoders for this scope.

	return result;
}

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
	struct IFF_Parser_Factory* factory,
	int file_handle
)
{
	char result;

	if (!item || !factory || !item->session)
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

	item->factory = factory;

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

	if (!parser || !parser->session || !parser->reader || !parser->factory)
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

		// Find and execute the ' IFF' directive processor.
		char (*processor)
		(
			const struct IFF_Chunk *chunk,
			struct IFF_DirectiveResult *result
		) = 0;

		if (VPS_Dictionary_Find(parser->factory->directive_processors, &iff_chunk->tag, (void**)&processor))
		{
			struct IFF_DirectiveResult result;
			if (processor(iff_chunk, &result))
			{
				// The processor successfully parsed the chunk. Now execute the command.
				switch (result.action)
				{
					case IFF_ACTION_UPDATE_FLAGS:
						IFF_Parser_Session_SetFlags(session, result.payload.new_flags);
						break;
					case IFF_ACTION_HALT:
						// The directive requested a halt (e.g., unsupported feature).
						IFF_Chunk_Release(iff_chunk);
						return 0; // Halt parsing.
					default:
						// Other actions are not expected from the ' IFF' directive.
						break;
				}
			}
		}

		// We are done with the ' IFF' chunk.
		IFF_Chunk_Release(iff_chunk);

		// After processing the directive, we start the main
		// recursive scan on the *next* chunk.
		return IFF_Parser_PRIVATE_ScanScope(parser);
	}
	else
	{
		// --- Case 2: File does NOT start with ' IFF'. ---
		// Per spec, it's a classic IFF-85 file. The default flags are correct.

		// We must validate that the tag is a valid container type.
		VPS_TYPE_16S container_ordering;
		IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_FORM, &container_ordering);
		if (container_ordering != 0)
		{
			IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_LIST, &container_ordering);
		}
		if (container_ordering != 0)
		{
			IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_CAT, &container_ordering);
		}

		if (container_ordering != 0) return 0; // Malformed: Must start with ' IFF' or a container.

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
