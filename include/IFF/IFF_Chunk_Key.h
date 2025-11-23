struct IFF_Chunk_Key
{
	struct IFF_Tag form;
	struct IFF_Tag prop;
};

char IFF_Chunk_Key_Allocate
(
	struct IFF_Chunk_Key **key
);

char IFF_Chunk_Key_Construct
(
	struct IFF_Chunk_Key *key,
	const struct IFF_Tag* form_tag,
	const struct IFF_Tag* prop_tag
);

char IFF_Chunk_Key_Deconstruct
(
	struct IFF_Chunk_Key *key
);

char IFF_Chunk_Key_Release
(
	struct IFF_Chunk_Key *key
);

char IFF_Chunk_Key_Hash
(
	void *key
	, VPS_TYPE_SIZE *key_hash
);

char IFF_Chunk_Key_Compare
(
	void *key_1
	, void *key_2
	, VPS_TYPE_16S *ordering
);

char IFF_Chunk_Key_Clone
(
	struct IFF_Chunk_Key *key,
	struct IFF_Chunk_Key **clone
);
