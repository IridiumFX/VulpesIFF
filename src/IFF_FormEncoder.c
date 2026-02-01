#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_FormEncoder.h>

char IFF_FormEncoder_Allocate
(
	struct IFF_FormEncoder **item
)
{
	if (!item)
	{
		return 0;
	}

	*item = calloc(1, sizeof(struct IFF_FormEncoder));

	return (*item != 0);
}

char IFF_FormEncoder_Construct
(
	struct IFF_FormEncoder *item
	, char (*begin_encode)(struct IFF_Generator_State*, void*, void**)
	, char (*produce_chunk)(struct IFF_Generator_State*, void*, struct IFF_Tag*, struct VPS_Data**, char*)
	, char (*produce_nested_form)(struct IFF_Generator_State*, void*, struct IFF_Tag*, void**, char*)
	, char (*end_encode)(struct IFF_Generator_State*, void*)
)
{
	if (!item)
	{
		return 0;
	}

	item->begin_encode = begin_encode;
	item->produce_chunk = produce_chunk;
	item->produce_nested_form = produce_nested_form;
	item->end_encode = end_encode;

	return 1;
}

char IFF_FormEncoder_Deconstruct
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
	}

	return 1;
}

char IFF_FormEncoder_Release
(
	struct IFF_FormEncoder *item
)
{
	if (item)
	{
		IFF_FormEncoder_Deconstruct(item);
		free(item);
	}

	return 1;
}
