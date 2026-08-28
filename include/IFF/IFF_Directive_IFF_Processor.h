#pragma once

#include <IFF/IFF_Result.h>


IFF_TYPE_RESULT IFF_Directive_IFF_Process
(
	const struct IFF_Chunk *chunk,
	struct IFF_DirectiveResult *result
);
