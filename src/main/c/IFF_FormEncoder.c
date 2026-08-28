#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_FormEncoder.h>

IFF_TYPE_RESULT IFF_FormEncoder_Allocate
(
	struct IFF_FormEncoder **item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	*item = calloc(1, sizeof(struct IFF_FormEncoder));

	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormEncoder_Construct
(
	struct IFF_FormEncoder *item
	, IFF_TYPE_RESULT (*begin_encode)(struct IFF_Generator_State*, void*, void**)
	, IFF_TYPE_RESULT (*produce_chunk)(struct IFF_Generator_State*, void*, struct IFF_Tag*, struct VPS_Data**, char*)
	, IFF_TYPE_RESULT (*produce_nested_form)(struct IFF_Generator_State*, void*, struct IFF_Tag*, void**, char*)
	, IFF_TYPE_RESULT (*end_encode)(struct IFF_Generator_State*, void*)
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->begin_encode = begin_encode;
	item->produce_chunk = produce_chunk;
	item->produce_nested_form = produce_nested_form;
	item->end_encode = end_encode;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormEncoder_Deconstruct
(
	struct IFF_FormEncoder *item
)
{
	if (item)
	{
		item->begin_encode = 0;
		item->produce_chunk = 0;
		item->produce_nested_form = 0;
		item->end_encode = 0;
		item->begin_container_group = 0;
		item->produce_grouped_form = 0;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormEncoder_Release
(
	struct IFF_FormEncoder *item
)
{
	if (item)
	{
		IFF_FormEncoder_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

char IFF_FormEncoder_VPS_Release
(
	void *item
)
{
	return IFF_FormEncoder_Release(item) == IFF_OK;
}
