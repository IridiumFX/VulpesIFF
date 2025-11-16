/*
 * NOTE:
 * All tags are normalized to a 16-byte canonical representation before being used for processor lookups.
 * This is achieved by padding shorter tags with space characters.
 * This design ensures that a processor registered for a 4-byte tag (e.g., 'ILBM')
 * will be correctly invoked for its 8-byte ('ILBM    ') and 16-byte ('ILBM            ') equivalents,
 * providing automatic forward compatibility.
 */

// sync to IFF_Header.h / enum IFF_Header_TagSizing
#define IFF_TAG_CANONICAL_SIZE 16

enum IFF_Tag_Type
{
    IFF_TAG_TYPE_TAG,       // A standard tag, right-padded (e.g., 'FORM' -> 'FORM    ')
    IFF_TAG_TYPE_DIRECTIVE  // A directive, left-padded (e.g., ' IFF' -> '    IFF')
};

struct IFF_Tag
{
    enum IFF_Tag_Type type;
	unsigned char data[IFF_TAG_CANONICAL_SIZE];
};

// --- System Tag Constants ---
extern const struct IFF_Tag IFF_TAG_SYSTEM_IFF;
extern const struct IFF_Tag IFF_TAG_SYSTEM_SHARD;
extern const struct IFF_Tag IFF_TAG_SYSTEM_END;
extern const struct IFF_Tag IFF_TAG_SYSTEM_LIST;
extern const struct IFF_Tag IFF_TAG_SYSTEM_CAT;
extern const struct IFF_Tag IFF_TAG_SYSTEM_FORM;
extern const struct IFF_Tag IFF_TAG_SYSTEM_PROP;
extern const struct IFF_Tag IFF_TAG_SYSTEM_VER;
extern const struct IFF_Tag IFF_TAG_SYSTEM_REV;
extern const struct IFF_Tag IFF_TAG_SYSTEM_CHK;
extern const struct IFF_Tag IFF_TAG_SYSTEM_SUM;

char IFF_Tag_Allocate
(
	struct IFF_Tag **tag
);

char IFF_Tag_Construct
(
	struct IFF_Tag *tag
	, const unsigned char *raw_data
	, VPS_TYPE_8U raw_size
	, enum IFF_Tag_Type type
);

char IFF_Tag_Deconstruct
(
	struct IFF_Tag *tag
);

char IFF_Tag_Release
(
	struct IFF_Tag *tag
);

char IFF_Tag_Clone
(
	const struct IFF_Tag *source
	, struct IFF_Tag **clone
);

char IFF_Tag_Compare
(
	const struct IFF_Tag *tag1
	, const struct IFF_Tag *tag2
	, VPS_TYPE_16S *ordering
);

char IFF_Tag_Hash
(
	const struct IFF_Tag *tag
	, VPS_TYPE_SIZE *hash
);
