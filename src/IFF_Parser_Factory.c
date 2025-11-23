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

	if (!VPS_Dictionary_Allocate(&subject->directive_processors, 17))
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
	VPS_Dictionary_Construct
	(
		item->directive_processors,
		(char(*)(void*, VPS_TYPE_SIZE*)) IFF_Tag_Hash,
		(char(*)(void*, void*, VPS_TYPE_16S*)) IFF_Tag_Compare,
		(char(*)(void*)) IFF_Tag_Release,
		0, // Processors are function pointers, not owned.
		2,
		7500,
		8
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
	VPS_Dictionary_Deconstruct
	(
		item->directive_processors
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
		VPS_Dictionary_Release
		(
			item->directive_processors
		);
		free(item);
	}

	return 1;
}

char IFF_Parser_Factory_RegisterFormDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Tag* form_tag
	, struct IFF_FormDecoder *decoder
)
{
	struct IFF_Tag *key_clone;

	if (!item || !item->form_decoders || !form_tag || !decoder)
	{
		return 0;
	}

	// Clone the provided key so the dictionary can own it.
	if (!IFF_Tag_Clone(form_tag, &key_clone)) return 0;

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->form_decoders, key_clone, decoder);
}

char IFF_Parser_Factory_RegisterChunkDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Chunk_Key* chunk_key
	, struct IFF_ChunkDecoder *decoder
)
{
	struct IFF_Chunk_Key *key_clone;

	if (!item || !item->chunk_decoders || !chunk_key || !decoder)
	{
		return 0;
	}

	// Clone the provided key so the dictionary can own it.
	if (!IFF_Chunk_Key_Allocate(&key_clone)) return 0;
	*key_clone = *chunk_key; // Safe by-value copy

	// Add to the dictionary. The dictionary now owns the key via its key_release callback.
	return VPS_Dictionary_Add(item->chunk_decoders, key_clone, decoder);
}

char IFF_Parser_Factory_RegisterDirectiveProcessor
(
	struct IFF_Parser_Factory* item,
	const struct IFF_Tag* directive_tag,
	char (*directive_processor)(struct IFF_Parser*, const struct IFF_Chunk*)
)
{
	struct IFF_Tag* key_clone;

	if (!item || !item->directive_processors || !directive_tag || !directive_processor)
	{
		return 0;
	}

	// Clone the provided key so the dictionary can own it.
	if (!IFF_Tag_Clone(directive_tag, &key_clone)) return 0;

	return VPS_Dictionary_Add(item->directive_processors, key_clone, directive_processor);
}

char IFF_Parser_Factory_Create
(
	struct IFF_Parser_Factory *factory,
	int file_handle,
	struct IFF_Parser **out_parser
)
{
	struct IFF_Parser *parser;
	char result;

	if (!factory || !out_parser)
	{
		return 0;
	}

	result = IFF_Parser_Allocate
	(
		&parser
	);
	if (!result)
	{
		return 0;
	}

	result = IFF_Parser_Construct
	(
		parser,
		factory->form_decoders,
		factory->chunk_decoders,
		factory->directive_processors,
		file_handle
	);
	if (!result)
	{
		goto failure;
	}

	*out_parser = parser;

	return 1;

failure:

	IFF_Parser_Release(parser);

	*out_parser = 0;

	return 0;
}
