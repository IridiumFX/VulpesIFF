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
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, int file_handle
)
{
	char result;

	if (!item || !form_decoders || !chunk_decoders || !directive_processors || !item->session)
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
char IFF_Parser_ExecuteDirective
(
	struct IFF_Parser *parser,
	struct IFF_Chunk *directive_chunk
)
{
	if (!parser || !directive_chunk)
	{
		return 0;
	}

	// Find and execute the ' IFF' directive processor.
	char (*processor)
	(
		const struct IFF_Chunk *chunk,
		struct IFF_DirectiveResult *result
	) = 0;

	if (VPS_Dictionary_Find(parser->directive_processors, &directive_chunk->tag, (void**)&processor))
	{
		struct IFF_DirectiveResult result;
		if (processor(directive_chunk, &result))
		{
			// The processor successfully parsed the chunk. Now execute the command.
			switch (result.action)
			{
				case IFF_ACTION_UPDATE_FLAGS:
					parser->session->current_scope->flags = result.payload.new_flags;
					break;
				case IFF_ACTION_HALT:
					// The directive requested a halt (e.g., unsupported feature).
					return 0; // Halt parsing.
				default:
					// Other actions are not expected from the ' IFF' directive.
					break;
			}
		}
	}

	return 1;
}

static char PRIVATE_IFF_Parser_Parse_FORM
(
	struct IFF_Parser *parser
	, struct IFF_Tag tag
)
{
	union IFF_Header_Flags current_flags = parser->session->current_scope->flags;
	VPS_TYPE_SIZE size = 0;

	if (current_flags.as_fields.operating == IFF_Header_Operating_BLOBBED)
	{
		IFF_Reader_ReadSize(parser->reader, current_flags.as_fields.sizing, current_flags.as_fields.typing, &size);
	}

	// todo: start chunk scanning loop

	return 0;
}

char IFF_Parser_Scan
(
	struct IFF_Parser *parser
)
{
	struct IFF_Parser_Session* session;
	struct IFF_Tag first_tag;
	union IFF_Header_Flags* current_flags;
	char result;

	if (!parser || !parser->session || !parser->reader)
	{
		return 0;
	}

	session = parser->session;
	current_flags = &session->current_scope->flags;

	// 1. Read the very first tag from the stream using the default IFF-85 flags.
	if (!IFF_Reader_ReadTag(parser->reader, current_flags->as_fields.tag_sizing, &first_tag))
	{
		// Empty file is not an error, just nothing to do.
		session->final_entity = 0;
		return 1;
	}

	// ' IFF' directive
	// ----------------
	VPS_TYPE_16S ordering;
	IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_IFF, &ordering);
	if (ordering == 0)
	{
		struct IFF_Chunk* iff_chunk = 0;

		// Read the rest of the ' IFF' chunk (size and data).
		if (!IFF_Reader_ReadChunk(parser->reader, &current_flags->as_fields, &first_tag, &iff_chunk))
		{
			return 0; // Malformed file.
		}

		// Execute the directive and dispose of the chunk
		result = IFF_Parser_ExecuteDirective(parser, iff_chunk);
		IFF_Chunk_Release(iff_chunk);

		if (!result)
		{
			return 0;
		}

		// Read the next tag to get back to the main flow.
		if (!IFF_Reader_ReadTag(parser->reader, current_flags->as_fields.tag_sizing, &first_tag))
		{
			// Empty file is not an error, just nothing to do.
			session->final_entity = 0;
			return 1;
		}

		// A second IFF directive in the outer scope is not allowed
		IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_IFF, &ordering);
		if (ordering == 0)
		{
			return 0;
		}
	}

	// Non directive flow
	// ------------------

	// We must validate that the tag is a valid container type.
	VPS_TYPE_16S container_ordering;
	IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_FORM, &container_ordering);
	if (container_ordering == 0)
	{
		result = PRIVATE_IFF_Parser_Parse_FORM(parser, first_tag);
		// TODO: Final boundary validation
		return 1;
	}

	IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_LIST, &container_ordering);
	if (container_ordering == 0)
	{
		// scan list
		return 1;
	}

	IFF_Tag_Compare(&first_tag, &IFF_TAG_SYSTEM_CAT, &container_ordering);
	if (container_ordering == 0)
	{
		// scan cat
		return 1;
	}

	return 0;
}
