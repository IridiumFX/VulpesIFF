#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Chunk.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_DirectiveResult.h>
#include <IFF/IFF_Directive_IFF_Processor.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Factory.h>

IFF_TYPE_RESULT IFF_Parser_Factory_Allocate
(
	struct IFF_Parser_Factory **item
)
{
	struct IFF_Parser_Factory *subject;

	if (!item)
	{
		return IFF_FAIL;
	}

	subject = calloc(1, sizeof(struct IFF_Parser_Factory));
	if (!subject)
	{
		return IFF_FAIL;
	}

	if (VPS_Dictionary_Allocate(&subject->form_decoders, 17))
	{
		goto failure;
	}

	if (VPS_Dictionary_Allocate(&subject->chunk_decoders, 17))
	{
		goto failure;
	}

	if (VPS_Dictionary_Allocate(&subject->directive_processors, 17))
	{
		goto failure;
	}

	*item = subject;

	return IFF_OK;

failure:

	IFF_Parser_Factory_Release(subject);

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_Parser_Factory_Construct
(
	struct IFF_Parser_Factory *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	VPS_Dictionary_Construct
	(
		item->form_decoders
		, IFF_Tag_VPS_Hash
		, IFF_Tag_VPS_Compare
		, IFF_Tag_VPS_Release
		, IFF_FormDecoder_VPS_Release // Registered decoders are owned by the factory
		, 2
		, 7500
		, 8
	);
	VPS_Dictionary_Construct
	(
		item->chunk_decoders
		, IFF_Chunk_Key_Hash
		, IFF_Chunk_Key_Compare
		, IFF_Chunk_Key_VPS_Release
		, IFF_ChunkDecoder_VPS_Release // Registered decoders are owned by the factory
		, 2
		, 7500
		, 8
	);
	VPS_Dictionary_Construct
	(
		item->directive_processors,
		IFF_Tag_VPS_Hash,
		IFF_Tag_VPS_Compare,
		IFF_Tag_VPS_Release,
		0, // Processors are function pointers, not owned.
		2,
		7500,
		8
	);

	// Register the built-in processor for the ' IFF' directive. Without it
	// every IFF-2025 stream would silently parse with IFF-85 defaults.
	return IFF_Parser_Factory_RegisterDirectiveProcessor(item, &IFF_TAG_SYSTEM_IFF, IFF_Directive_IFF_Process);
}

IFF_TYPE_RESULT IFF_Parser_Factory_Deconstruct
(
	struct IFF_Parser_Factory *item
)
{
	if (!item)
	{
		return IFF_FAIL;
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

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Parser_Factory_Release
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

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Parser_Factory_RegisterFormDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Tag* form_tag
	, struct IFF_FormDecoder *decoder
)
{
	struct IFF_Tag *key_clone;
	char existed;
	VPS_TYPE_RESULT result;

	if (!item || !item->form_decoders || !form_tag || !decoder)
	{
		return IFF_FAIL;
	}

	// Clone the provided key so the dictionary can own it.
	if (IFF_Tag_Clone(form_tag, &key_clone))
	{
		return IFF_FAIL;
	}

	// Add consumes the clone only when it creates a new entry; on the
	// re-registration path the dictionary keeps its original key (and
	// releases the replaced decoder), and on failure nothing is stored.
	existed = VPS_Dictionary_Find(item->form_decoders, key_clone, 0);
	result = VPS_Dictionary_Add(item->form_decoders, key_clone, decoder);

	if (existed || result)
	{
		IFF_Tag_Release(key_clone);
	}

	if (result)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Parser_Factory_RegisterChunkDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Chunk_Key* chunk_key
	, struct IFF_ChunkDecoder *decoder
)
{
	struct IFF_Chunk_Key *key_clone;
	char existed;
	VPS_TYPE_RESULT result;

	if (!item || !item->chunk_decoders || !chunk_key || !decoder)
	{
		return IFF_FAIL;
	}

	// Clone the provided key so the dictionary can own it.
	if (IFF_Chunk_Key_Allocate(&key_clone)) return IFF_FAIL;
	*key_clone = *chunk_key; // Safe by-value copy

	// Add consumes the clone only when it creates a new entry (see
	// RegisterFormDecoder).
	existed = VPS_Dictionary_Find(item->chunk_decoders, key_clone, 0);
	result = VPS_Dictionary_Add(item->chunk_decoders, key_clone, decoder);

	if (existed || result)
	{
		IFF_Chunk_Key_Release(key_clone);
	}

	if (result)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Parser_Factory_RegisterDirectiveProcessor
(
	struct IFF_Parser_Factory* item,
	const struct IFF_Tag* directive_tag,
	IFF_TYPE_RESULT (*processor)
	(
		const struct IFF_Chunk *chunk,
		struct IFF_DirectiveResult *result
	)
)
{
	struct IFF_Tag* key_clone;
	char existed;
	VPS_TYPE_RESULT result;

	if (!item || !item->directive_processors || !directive_tag || !processor)
	{
		return IFF_FAIL;
	}

	// Clone the provided key so the dictionary can own it.
	if (IFF_Tag_Clone(directive_tag, &key_clone))
	{
		return IFF_FAIL;
	}

	// Add consumes the clone only when it creates a new entry (see
	// RegisterFormDecoder).
	existed = VPS_Dictionary_Find(item->directive_processors, key_clone, 0);
	result = VPS_Dictionary_Add(item->directive_processors, key_clone, processor);

	if (existed || result)
	{
		IFF_Tag_Release(key_clone);
	}

	if (result)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Parser_Factory_Create
(
	struct IFF_Parser_Factory *factory,
	int file_handle,
	struct IFF_Parser **out_parser
)
{
	struct IFF_Parser *parser;
	IFF_TYPE_RESULT result;

	if (!factory || !out_parser)
	{
		return IFF_FAIL;
	}

	result = IFF_Parser_Allocate
	(
		&parser
	);
	if (result)
	{
		return result;
	}

	result = IFF_Parser_Construct
	(
		parser,
		factory->form_decoders,
		factory->chunk_decoders,
		factory->directive_processors,
		file_handle
	);
	if (result)
	{
		goto failure;
	}

	*out_parser = parser;

	return IFF_OK;

failure:

	IFF_Parser_Release(parser);

	*out_parser = 0;

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_Parser_Factory_CreateFromData
(
	struct IFF_Parser_Factory *factory
	, const struct VPS_Data *source
	, struct IFF_Parser **out_parser
)
{
	struct IFF_Parser *parser;

	if (!factory || !source || !out_parser)
	{
		return IFF_FAIL;
	}

	if (IFF_Parser_Allocate(&parser))
	{
		return IFF_FAIL;
	}

	if
	(
		IFF_Parser_ConstructFromData
		(
			parser
			, factory->form_decoders
			, factory->chunk_decoders
			, factory->directive_processors
			, source
		)
	)
	{
		IFF_Parser_Release(parser);
		*out_parser = 0;
		return IFF_FAIL;
	}

	*out_parser = parser;

	return IFF_OK;
}
