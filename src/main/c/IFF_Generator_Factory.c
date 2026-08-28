#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

IFF_TYPE_RESULT IFF_Generator_Factory_Allocate
(
	struct IFF_Generator_Factory **item
)
{
	struct IFF_Generator_Factory *factory;

	if (!item)
	{
		return IFF_FAIL;
	}

	factory = calloc(1, sizeof(struct IFF_Generator_Factory));
	if (!factory)
	{
		return IFF_FAIL;
	}

	if (VPS_Dictionary_Allocate(&factory->form_encoders, 17))
	{
		goto failure;
	}

	if (VPS_Dictionary_Allocate(&factory->chunk_encoders, 17))
	{
		goto failure;
	}

	*item = factory;

	return IFF_OK;

failure:

	IFF_Generator_Factory_Release(factory);

	return IFF_FAIL;
}

IFF_TYPE_RESULT IFF_Generator_Factory_Construct
(
	struct IFF_Generator_Factory *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	VPS_Dictionary_Construct
	(
		item->form_encoders
		, IFF_Tag_VPS_Hash
		, IFF_Tag_VPS_Compare
		, IFF_Tag_VPS_Release
		, IFF_FormEncoder_VPS_Release // Registered encoders are owned by the factory
		, 2
		, 7500
		, 8
	);

	VPS_Dictionary_Construct
	(
		item->chunk_encoders
		, IFF_Tag_VPS_Hash
		, IFF_Tag_VPS_Compare
		, IFF_Tag_VPS_Release
		, IFF_ChunkEncoder_VPS_Release // Registered encoders are owned by the factory
		, 2
		, 7500
		, 8
	);

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Generator_Factory_Deconstruct
(
	struct IFF_Generator_Factory *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	VPS_Dictionary_Deconstruct(item->form_encoders);
	VPS_Dictionary_Deconstruct(item->chunk_encoders);

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Generator_Factory_Release
(
	struct IFF_Generator_Factory *item
)
{
	if (item)
	{
		IFF_Generator_Factory_Deconstruct(item);
		VPS_Dictionary_Release(item->form_encoders);
		VPS_Dictionary_Release(item->chunk_encoders);
		free(item);
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Generator_Factory_RegisterFormEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *form_tag
	, struct IFF_FormEncoder *encoder
)
{
	struct IFF_Tag *key_clone;
	char existed;
	VPS_TYPE_RESULT result;

	if (!item || !item->form_encoders || !form_tag || !encoder)
	{
		return IFF_FAIL;
	}

	if (IFF_Tag_Clone(form_tag, &key_clone))
	{
		return IFF_FAIL;
	}

	// Add consumes the clone only when it creates a new entry; on the
	// re-registration path the dictionary keeps its original key (and
	// releases the replaced encoder), and on failure nothing is stored.
	existed = VPS_Dictionary_Find(item->form_encoders, key_clone, 0);
	result = VPS_Dictionary_Add(item->form_encoders, key_clone, encoder);

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

IFF_TYPE_RESULT IFF_Generator_Factory_RegisterChunkEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *chunk_tag
	, struct IFF_ChunkEncoder *encoder
)
{
	struct IFF_Tag *key_clone;
	char existed;
	VPS_TYPE_RESULT result;

	if (!item || !item->chunk_encoders || !chunk_tag || !encoder)
	{
		return IFF_FAIL;
	}

	if (IFF_Tag_Clone(chunk_tag, &key_clone))
	{
		return IFF_FAIL;
	}

	// Add consumes the clone only when it creates a new entry (see
	// RegisterFormEncoder).
	existed = VPS_Dictionary_Find(item->chunk_encoders, key_clone, 0);
	result = VPS_Dictionary_Add(item->chunk_encoders, key_clone, encoder);

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

IFF_TYPE_RESULT IFF_Generator_Factory_Create
(
	struct IFF_Generator_Factory *factory
	, int file_handle
	, struct IFF_Generator **out_generator
)
{
	struct IFF_Generator *gen;

	if (!factory || !out_generator)
	{
		return IFF_FAIL;
	}

	if (IFF_Generator_Allocate(&gen))
	{
		return IFF_FAIL;
	}

	if (IFF_Generator_Construct(gen, file_handle))
	{
		IFF_Generator_Release(gen);
		return IFF_FAIL;
	}

	/* Transfer encoder registries to the generator (borrowed, not owned) */
	gen->form_encoders = factory->form_encoders;
	gen->chunk_encoders = factory->chunk_encoders;

	*out_generator = gen;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Generator_Factory_CreateToData
(
	struct IFF_Generator_Factory *factory
	, struct IFF_Generator **out_generator
)
{
	struct IFF_Generator *gen;

	if (!factory || !out_generator)
	{
		return IFF_FAIL;
	}

	if (IFF_Generator_Allocate(&gen))
	{
		return IFF_FAIL;
	}

	if (IFF_Generator_ConstructToData(gen))
	{
		IFF_Generator_Release(gen);
		return IFF_FAIL;
	}

	gen->form_encoders = factory->form_encoders;
	gen->chunk_encoders = factory->chunk_encoders;

	*out_generator = gen;

	return IFF_OK;
}
