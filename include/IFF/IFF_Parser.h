#pragma once

#include <IFF/IFF_Result.h>

struct VPS_Data;
struct IFF_Chunk;

typedef IFF_TYPE_RESULT (*IFF_SegmentResolverFn)
(
	void *context,
	const struct VPS_Data *identifier,
	int *out_file_handle
);

/**
 * @brief Deepest container nesting the parser will follow.
 * @details Containers recurse, so a file's nesting depth becomes the
 *          parser's call depth. A container header is twelve bytes, so
 *          without a ceiling an 84 KB file of nothing but nested 'CAT '
 *          headers exhausts a one-megabyte stack and the process dies
 *          inside the allocator, far from the cause.
 *
 *          Real files are shallow -- the IFF-85 examples nest three or
 *          four levels -- so this is set far above anything legitimate
 *          and far below anything dangerous. Exceeding it fails the
 *          parse like any other malformed input.
 */
#define IFF_PARSER_MAX_NESTING_DEPTH 64

struct IFF_Parser
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
	struct VPS_Dictionary *directive_processors;

	struct IFF_Parser_Session *session;
	struct IFF_Reader *reader;

	int file_handle;

	IFF_SegmentResolverFn segment_resolver;
	void *resolver_context;
	struct VPS_List *reader_stack;

	/**
	 * @brief When set, mandatory ' REF' directives fail if no resolver
	 *        is registered. When clear (default), unresolved REFs are
	 *        silently consumed for forward compatibility.
	 */
	char strict_references;

	/**
	 * @brief Container nesting currently being parsed.
	 * @details Containers are parsed by recursion, one frame pair per
	 *          level, so this is also the call depth. It is bounded by
	 *          IFF_PARSER_MAX_NESTING_DEPTH; see there for why.
	 */
	VPS_TYPE_SIZE nesting_depth;
};

IFF_TYPE_RESULT IFF_Parser_Allocate
(
	struct IFF_Parser **item
);

IFF_TYPE_RESULT IFF_Parser_Construct
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, int file_handle
);

IFF_TYPE_RESULT IFF_Parser_ConstructFromData
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, const struct VPS_Data *source
);

IFF_TYPE_RESULT IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
);

IFF_TYPE_RESULT IFF_Parser_Release
(
	struct IFF_Parser *item
);

IFF_TYPE_RESULT IFF_Parser_ExecuteDirective
(
	struct IFF_Parser *parser,
	struct IFF_Chunk *directive_chunk
);

IFF_TYPE_RESULT IFF_Parser_Scan
(
	struct IFF_Parser *parser
);

IFF_TYPE_RESULT IFF_Parser_SetSegmentResolver
(
	struct IFF_Parser *parser,
	IFF_SegmentResolverFn resolver,
	void *context
);
