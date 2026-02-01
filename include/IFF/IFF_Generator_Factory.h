struct IFF_Tag;
struct IFF_FormEncoder;
struct IFF_ChunkEncoder;
struct IFF_Generator;

/**
 * @brief Builder pattern for constructing configured IFF_Generator instances.
 * @details Mirrors IFF_Parser_Factory for the read-side. Allows registration
 *          of FormEncoder and ChunkEncoder vtables, then creates a Generator
 *          with those registries attached.
 */
struct IFF_Generator_Factory
{
	struct VPS_Dictionary *form_encoders;
	struct VPS_Dictionary *chunk_encoders;
};

char IFF_Generator_Factory_Allocate
(
	struct IFF_Generator_Factory **item
);

char IFF_Generator_Factory_Construct
(
	struct IFF_Generator_Factory *item
);

char IFF_Generator_Factory_Deconstruct
(
	struct IFF_Generator_Factory *item
);

char IFF_Generator_Factory_Release
(
	struct IFF_Generator_Factory *item
);

char IFF_Generator_Factory_RegisterFormEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *form_tag
	, struct IFF_FormEncoder *encoder
);

char IFF_Generator_Factory_RegisterChunkEncoder
(
	struct IFF_Generator_Factory *item
	, const struct IFF_Tag *chunk_tag
	, struct IFF_ChunkEncoder *encoder
);

char IFF_Generator_Factory_Create
(
	struct IFF_Generator_Factory *factory
	, int file_handle
	, struct IFF_Generator **out_generator
);

char IFF_Generator_Factory_CreateToData
(
	struct IFF_Generator_Factory *factory
	, struct IFF_Generator **out_generator
);
