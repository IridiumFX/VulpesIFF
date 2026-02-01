#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

char IFF_Generator_Factory_Allocate
(
	struct IFF_Generator_Factory **item
)
{
	struct IFF_Generator_Factory *factory;

	if (!item)
	{
		return 0;
	}

	factory = calloc(1, sizeof(struct IFF_Generator_Factory));
	if (!factory)
	{
		return 0;
	}

	if (!VPS_Dictionary_Allocate(&factory->form_encoders, 17))
	{
		goto failure;
	}

	if (!VPS_Dictionary_Allocate(&factory->chunk_encoders, 17))
	{
		goto failure;
	}

	*item = factory;

	return 1;

failure:

	IFF_Generator_Factory_Release(factory);

	return 0;
}

char IFF_Generator_Factory_Construct
(
	struct IFF_Generator_Factory *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Construct
	(
		item->form_encoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Tag_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Tag_Compare
		, (char (*)(void *)) IFF_Tag_Release
		, 0
		, 2
		, 7500
		, 8
	);

	VPS_Dictionary_Construct
	(
		item->chunk_encoders
		, (char (*)(void *, VPS_TYPE_SIZE *)) IFF_Tag_Hash
		, (char (*)(void *, void *, VPS_TYPE_16S *)) IFF_Tag_Compare
		, (char (*)(void *)) IFF_Tag_Release
		, 0
		, 2
		, 7500
		, 8
	);

	return 1;
}

char IFF_Generator_Factory_Deconstruct
(
	struct IFF_Generator_Factory *item
)
{
	if (!item)
	{
		return 0;
	}

	VPS_Dictionary_Deconstruct(item->form_encoders);
	VPS_Dictionary_Deconstruct(item->chunk_encoders);

	return 1;
}

char IFF_Generator_Factory_Release
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

	return 1;
}

char IFF_Generator_Factory_RegisterFormEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *form_tag
	, struct IFF_FormEncoder *encoder
)
{
	struct IFF_Tag *key_clone;

	if (!item || !item->form_encoders || !form_tag || !encoder)
	{
		return 0;
	}

	if (!IFF_Tag_Clone(form_tag, &key_clone))
	{
		return 0;
	}

	return VPS_Dictionary_Add(item->form_encoders, key_clone, encoder);
}

char IFF_Generator_Factory_RegisterChunkEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *chunk_tag
	, struct IFF_ChunkEncoder *encoder
)
{
	struct IFF_Tag *key_clone;

	if (!item || !item->chunk_encoders || !chunk_tag || !encoder)
	{
		return 0;
	}

	if (!IFF_Tag_Clone(chunk_tag, &key_clone))
	{
		return 0;
	}

	return VPS_Dictionary_Add(item->chunk_encoders, key_clone, encoder);
}

char IFF_Generator_Factory_Create
(
	struct IFF_Generator_Factory *factory
	, int file_handle
	, struct IFF_Generator **out_generator
)
{
	struct IFF_Generator *gen;

	if (!factory || !out_generator)
	{
		return 0;
	}

	if (!IFF_Generator_Allocate(&gen))
	{
		return 0;
	}

	if (!IFF_Generator_Construct(gen, file_handle))
	{
		IFF_Generator_Release(gen);
		return 0;
	}

	/* Transfer encoder registries to the generator (borrowed, not owned) */
	gen->form_encoders = factory->form_encoders;
	gen->chunk_encoders = factory->chunk_encoders;

	*out_generator = gen;

	return 1;
}

char IFF_Generator_Factory_CreateToData
(
	struct IFF_Generator_Factory *factory
	, struct IFF_Generator **out_generator
)
{
	struct IFF_Generator *gen;

	if (!factory || !out_generator)
	{
		return 0;
	}

	if (!IFF_Generator_Allocate(&gen))
	{
		return 0;
	}

	if (!IFF_Generator_ConstructToData(gen))
	{
		IFF_Generator_Release(gen);
		return 0;
	}

	gen->form_encoders = factory->form_encoders;
	gen->chunk_encoders = factory->chunk_encoders;

	*out_generator = gen;

	return 1;
}
