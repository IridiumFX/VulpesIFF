#pragma once

#include <IFF/IFF_Result.h>

/**
 * @brief Encapsulates a block of data along with the parsing context (flags)
 *        that was active at the time of its creation.
 *
 * This is the standard "meaningful item" produced by chunk decoders. It ensures
 * that any component that consumes this data later can interpret it correctly,
 * regardless of any subsequent changes to the parser's state.
 */
struct IFF_ContextualData
{
	union IFF_Header_Flags flags;
	struct VPS_Data *data;
};

IFF_TYPE_RESULT IFF_ContextualData_Allocate
(
	struct IFF_ContextualData **item
);

IFF_TYPE_RESULT IFF_ContextualData_Construct
(
	struct IFF_ContextualData *item
	, union IFF_Header_Flags flags
	, struct VPS_Data *data
);

IFF_TYPE_RESULT IFF_ContextualData_Deconstruct
(
	struct IFF_ContextualData *item
);

IFF_TYPE_RESULT IFF_ContextualData_Release
(
	struct IFF_ContextualData *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * VulpesCore containers expect the boolean convention (1 = success).
 * Register this shim as the release hook rather than casting the function
 * above, whose polarity is inverted.
 */

char IFF_ContextualData_VPS_Release
(
	void *item
);
