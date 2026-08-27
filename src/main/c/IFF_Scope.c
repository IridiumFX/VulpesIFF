#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Boundary.h>
#include <IFF/IFF_Scope.h>

IFF_TYPE_RESULT IFF_Scope_Allocate
(
	struct IFF_Scope **item
)
{
	if (!item) return IFF_FAIL;
	*item = calloc(1, sizeof(struct IFF_Scope));
	if (!*item)
	{
		return IFF_FAIL;
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Scope_Construct
(
	struct IFF_Scope *item
	, union IFF_Header_Flags flags
	, struct IFF_Boundary boundary
	, struct IFF_Tag variant
	, struct IFF_Tag type
)
{
	if (!item) return IFF_FAIL;

	item->flags = flags;
	item->boundary = boundary;
	item->container_variant = variant;
	item->container_type = type;
	item->form_decoder = 0;
	item->form_state = 0;
	item->receiving_form_scope = 0;
	item->last_chunk_decoder = 0;
	item->last_chunk_state = 0;
	memset(&item->last_chunk_tag, 0, sizeof(struct IFF_Tag));

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Scope_Deconstruct
(
	struct IFF_Scope *item
)
{
	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Scope_Release
(
	struct IFF_Scope *item
)
{
	if (item)
	{
		// A release function should always deconstruct first.
		IFF_Scope_Deconstruct(item);
		free(item);
	}
	return IFF_OK;
}

// --- VulpesCore boundary adapter ---

char IFF_Scope_VPS_Release
(
	void *item
)
{
	return IFF_Scope_Release(item) == IFF_OK;
}
