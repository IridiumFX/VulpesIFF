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
	const unsigned char *raw_form_tag,
	const unsigned char *raw_prop_tag,
	VPS_TYPE_8U raw_tag_size
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
