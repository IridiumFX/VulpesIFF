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
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Scope_State.h>

char IFF_Parser_Factory_Allocate
(
	struct IFF_Parser_Factory **item
)
{
	struct IFF_Parser_Factory *subject;

	if (!item)
	{
		return 0;
	}

	subject = calloc(1, sizeof(struct IFF_Parser_Factory));
	if (!subject)
	{
		return 0;
	}

	if (!VPS_Dictionary_Allocate(&subject->form_decoders, 17))
	{
		goto failure;
	}

	if (!VPS_Dictionary_Allocate(&subject->chunk_decoders, 17))
	{
		goto failure;
	}

	*item = subject;

	return 1;

failure:

	IFF_Parser_Factory_Release(subject);

	return 0;
}

char IFF_Parser_Factory_Construct
(
	struct IFF_Parser_Factory *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Construct
	(
		item->form_decoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Tag_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Tag_Compare
		, (char (*)(void *)) IFF_Tag_Release
		, 0 // Processors are not owned by the dictionary
		, 2
		, 7500
		, 8
	);
	VPS_Dictionary_Construct
	(
		item->chunk_decoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Chunk_Key_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Chunk_Key_Compare
		, (char (*)(void *)) IFF_Chunk_Key_Release
		, 0 // Processors are not owned by the dictionary
		, 2
		, 7500
		, 8
	);

	return 1;
}

char IFF_Parser_Factory_Deconstruct
(
	struct IFF_Parser_Factory *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Deconstruct
	(
		item->form_decoders
	);
	VPS_Dictionary_Deconstruct
	(
		item->chunk_decoders
	);

	return 1;
}

char IFF_Parser_Factory_Release
(
	struct IFF_Parser_Factory *item
)
{
	if (item)
	{
		VPS_Dictionary_Release
		(
			item->chunk_decoders
		);
		VPS_Dictionary_Release
		(
			item->form_decoders
		);
		free(item);
	}

	return 1;
}

char IFF_Parser_Factory_RegisterFormDecoder
(
	struct IFF_Parser_Factory *item
	, const unsigned char *raw_form_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_FormDecoder *decoder
)
{
	struct IFF_Tag *form_tag;

	if (!item || !item->form_decoders || !raw_form_tag || !decoder)
	{
		return 0;
	}

	// The parser creates and will own the key.
	if (!IFF_Tag_Allocate(&form_tag))
	{
		return 0;
	}

	if (!IFF_Tag_Construct(form_tag, raw_form_tag, raw_tag_size, IFF_TAG_TYPE_TAG))
	{
		IFF_Tag_Release(form_tag);
		return 0;
	}

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->form_decoders, form_tag, decoder);
}

char IFF_Parser_Factory_RegisterChunkDecoder
(
	struct IFF_Parser_Factory *item
	, const unsigned char *raw_form_tag
	, const unsigned char *raw_chunk_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_ChunkDecoder *decoder
)
{
	struct IFF_Chunk_Key *key;

	if (!item || !item->chunk_decoders || !raw_form_tag || !raw_chunk_tag || !decoder)
	{
		return 0;
	}

	// The parser creates and will own the key.
	if (!IFF_Chunk_Key_Allocate(&key))
	{
		return 0;
	}

	// Construct the composite key from the raw tag data.
	if (!IFF_Chunk_Key_Construct(key, raw_form_tag, raw_chunk_tag, raw_tag_size))
	{
		IFF_Chunk_Key_Release(key);
		return 0;
	}

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->chunk_decoders, key, decoder);
}

char IFF_Parser_Factory_CreateSession
(
	struct IFF_Parser_Factory *factory,
	int file_handle,
	struct IFF_Parser_Session **state
)
{
	struct IFF_Parser_Session *parser_session;
	char result;

	if (!factory || !state)
	{
		return 0;
	}

	result = IFF_Parser_Session_Allocate(&parser_session);
	if (!result)
	{
		return 0;
	}

	result = IFF_Parser_Session_Construct(parser_session, factory, file_handle, IFF_HEADER_FLAGS_1985);
	if (!result)
	{
		goto failure;
	}

	*state = parser_session;

	return 1;

	failure:

		IFF_Parser_Session_Release(parser_session);

	return 0;
}