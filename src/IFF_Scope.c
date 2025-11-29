#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Boundary.h>
#include <IFF/IFF_Scope.h>

char IFF_Scope_Allocate
(
	struct IFF_Scope **item
)
{
	if (!item) return 0;
	*item = calloc(1, sizeof(struct IFF_Scope));
	return *item != 0;
}

char IFF_Scope_Construct
(
	struct IFF_Scope *item
	, union IFF_Header_Flags flags
	, struct IFF_Boundary boundary
	, struct IFF_Tag variant
	, struct IFF_Tag type
)
{
	if (!item) return 0;

	item->flags = flags;
	item->boundary = boundary;
	item->container_variant = variant;
	item->container_type = type;
	item->form_decoder = 0;
	item->form_state = 0;

	return 1;
}

char IFF_Scope_Deconstruct
(
	struct IFF_Scope *item
)
{
	return 1;
}

char IFF_Scope_Release
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
	return 1;
}