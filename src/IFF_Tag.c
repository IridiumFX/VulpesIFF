#include <stdlib.h>
#include <string.h>
#include <vulpes/VPS_Types.h>
#include <IFF/IFF_Tag.h>

// --- System Tag Constants (Normalized to 16 bytes with type) ---
const struct IFF_Tag IFF_TAG_SYSTEM_IFF =
{
    IFF_TAG_TYPE_DIRECTIVE
    , {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'I', 'F', 'F'}
};

const struct IFF_Tag IFF_TAG_SYSTEM_SHARD =
{
    IFF_TAG_TYPE_DIRECTIVE
    , {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
};

const struct IFF_Tag IFF_TAG_SYSTEM_END =
{
    IFF_TAG_TYPE_DIRECTIVE
    , {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'E', 'N', 'D'}
};

const struct IFF_Tag IFF_TAG_SYSTEM_LIST =
{
    IFF_TAG_TYPE_TAG
    , {'L', 'I', 'S', 'T', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
};

const struct IFF_Tag IFF_TAG_SYSTEM_CAT =
{
    IFF_TAG_TYPE_TAG
    , {'C', 'A', 'T', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
};

const struct IFF_Tag IFF_TAG_SYSTEM_FORM =
{
    IFF_TAG_TYPE_TAG
    , {'F', 'O', 'R', 'M', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
};

const struct IFF_Tag IFF_TAG_SYSTEM_PROP =
{
    IFF_TAG_TYPE_TAG
    , {'P', 'R', 'O', 'P', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
};

// --- Internal System Tag Constants (for parser context) ---
// These are used as keys in the scoped dictionary to track container context.
// They use non-standard characters to avoid collision with any valid IFF tag.
const struct IFF_Tag IFF_TAG_INTERNAL_VARIANT =
{
    IFF_TAG_TYPE_TAG,
    {'_', 'V', 'A', 'R', 'I', 'A', 'N', 'T', '_', '_', '_', '_', '_', '_', '_', '_'}
};

const struct IFF_Tag IFF_TAG_INTERNAL_TYPE =
{
    IFF_TAG_TYPE_TAG,
    {'_', 'T', 'Y', 'P', 'E', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_'}
};

char IFF_Tag_Allocate
(
    struct IFF_Tag **tag
)
{
    if (!tag) return 0;
    *tag = calloc(1, sizeof(struct IFF_Tag));
    return *tag != NULL;
}

char IFF_Tag_Construct
(
    struct IFF_Tag *tag
    , const unsigned char *raw_data
    , VPS_TYPE_8U raw_size
    , enum IFF_Tag_Type type
)
{
    if (!tag || !raw_data || (raw_size != 4 && raw_size != 8 && raw_size != 16))
    {
        return 0;
    }

    tag->type = type;
    memset(tag->data, ' ', IFF_TAG_CANONICAL_SIZE);

    if (type == IFF_TAG_TYPE_TAG)
    {
        memcpy(tag->data, raw_data, raw_size);
    }
    else // IFF_TAG_TYPE_DIRECTIVE
    {
        memcpy(tag->data + IFF_TAG_CANONICAL_SIZE - raw_size, raw_data, raw_size);
    }

    return 1;
}

char IFF_Tag_Deconstruct
(
    struct IFF_Tag *tag
)
{
    (void)tag;

    return 1;
}

char IFF_Tag_Release
(
    struct IFF_Tag *tag
)
{
    if (tag)
    {
        free(tag);
    }

    return 1;
}

char IFF_Tag_Clone
(
	const struct IFF_Tag *source
	, struct IFF_Tag **clone
)
{
	if (!source || !clone)
	{
		return 0;
	}

	if (!IFF_Tag_Allocate(clone))
	{
		return 0;
	}

	// Since IFF_Tag is a simple struct with no internal pointers,
	// a direct value copy is safe and efficient.
	**clone = *source;

	return 1;
}

char IFF_Tag_Compare
(
    const struct IFF_Tag *tag1
    , const struct IFF_Tag *tag2
    , VPS_TYPE_16S *ordering
)
{
    if (!tag1 || !tag2 || !ordering)
    {
        return 0;
    }

    if (tag1->type < tag2->type)
    {
        *ordering = -1;

        return 1;
    }
    if (tag1->type > tag2->type)
    {
        *ordering = 1;

        return 1;
    }

    int result = memcmp(tag1->data, tag2->data, IFF_TAG_CANONICAL_SIZE);

    if (result < 0)
    {
        *ordering = -1;
    }
    else if (result > 0)
    {
        *ordering = 1;
    }
    else
    {
        *ordering = 0;
    }

    return 1;
}

char IFF_Tag_Hash
(
    const struct IFF_Tag *tag
    , VPS_TYPE_SIZE *hash
)
{
    if (!tag || !hash)
    {
        return 0;
    }

    VPS_TYPE_64U h = 0xcbf29ce484222325ULL;
    
    // Hash the type field
    h = (h ^ (unsigned char)tag->type) * 0x100000001b3ULL;

    // Hash the data field
    for (int i = 0; i < IFF_TAG_CANONICAL_SIZE; ++i)
    {
        h = (h ^ tag->data[i]) * 0x100000001b3ULL;
    }

    *hash = (VPS_TYPE_SIZE)h;

    return 1;
}
