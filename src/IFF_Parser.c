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
	struct IFF_Parser *parser,
	struct IFF_Parser_Session *session
)
{
	return 0;
}
