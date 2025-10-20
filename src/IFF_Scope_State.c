#include <stdlib.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Scope_State.h>

char IFF_Scope_State_Allocate
(
	struct IFF_Scope_State **item
)
{
	if (!item) return 0;
	*item = calloc(1, sizeof(struct IFF_Scope_State));
	return *item != 0;
}

char IFF_Scope_State_Construct
(
	struct IFF_Scope_State *item
	, union IFF_Header_Flags flags
	, VPS_TYPE_64U boundary_size
    , struct IFF_Tag variant
    , struct IFF_Tag type
)
{
	if (!item) return 0;

	item->flags = flags;
	item->boundary_size = boundary_size;
	item->bytes_scanned = 0;
    item->container_variant = variant;
    item->container_type = type;
    item->form_decoder = 0;
    item->form_state = 0;

	return 1;
}

char IFF_Scope_State_Release
(
	struct IFF_Scope_State *item
)
{
	if (item)
	{
		free(item);
	}
	return 1;
}