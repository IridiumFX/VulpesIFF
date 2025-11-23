#include <IFF/IFF_DirectiveProcessor.h>

struct IFF_Parser_Factory
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
	struct VPS_Dictionary *directive_processors;
};

char IFF_Parser_Factory_Allocate
(
	struct IFF_Parser_Factory **item
);

char IFF_Parser_Factory_Construct
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_Deconstruct
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_Release
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_RegisterFormDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Tag* form_tag
	, struct IFF_FormDecoder *decoder
);

char IFF_Parser_Factory_RegisterChunkDecoder
(
	struct IFF_Parser_Factory *item,
	const struct IFF_Chunk_Key* chunk_key
	, struct IFF_ChunkDecoder *decoder
);

char IFF_Parser_Factory_RegisterDirectiveProcessor
(
	struct IFF_Parser_Factory* item,
	const struct IFF_Tag* directive_tag,
	char (*directive_processor)(struct IFF_Parser*, const struct IFF_Chunk*)
);

char IFF_Parser_Factory_Create
(
	struct IFF_Parser_Factory *factory
	, int file_handle
	, struct IFF_Parser **out_parser
);

char IFF_Parser_Factory_GetFinalEntity
(
	struct IFF_Parser_Session* session,
	void** entity
);