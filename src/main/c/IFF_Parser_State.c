#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_State.h>

char IFF_Parser_State_FindProp
(
	struct IFF_Parser_State *state
	, struct IFF_Tag *prop_tag
	, struct IFF_ContextualData **out_prop_data
)
{
	if (!state || !state->session)
	{
		return 0;
	}

	return IFF_Parser_Session_FindProp
	(
		state->session
		, prop_tag
		, out_prop_data
	);
}
