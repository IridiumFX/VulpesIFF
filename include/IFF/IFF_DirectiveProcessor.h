#pragma once

#include <IFF/IFF_Result.h>

struct IFF_Chunk;
struct IFF_DirectiveResult;

/**
 * @brief Signature of a directive processor callback.
 * @details Registered per directive tag via
 *          IFF_Parser_Factory_RegisterDirectiveProcessor. The processor
 *          inspects the directive chunk and reports the action the parser
 *          should take through the IFF_DirectiveResult out-parameter.
 *          Returns IFF_OK on success, non-zero when the directive payload is malformed
 *          (which fails the parse).
 */
typedef IFF_TYPE_RESULT (*IFF_DirectiveProcessor)
(
	const struct IFF_Chunk *chunk
	, struct IFF_DirectiveResult *result
);
