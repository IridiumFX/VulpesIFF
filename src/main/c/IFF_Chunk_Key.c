#include <string.h>
#include <stdlib.h>
#include <vulpes/VPS_Types.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>

char IFF_Chunk_Key_Allocate
(
	struct IFF_Chunk_Key **key
)
{
	if (!key)
	{
	    return 0;
	}

	*key = calloc(1, sizeof(struct IFF_Chunk_Key));

    return *key != 0;
}

char IFF_Chunk_Key_Construct
(
	struct IFF_Chunk_Key *key,
	const struct IFF_Tag* form_tag,
	const struct IFF_Tag* prop_tag
)
{
	if (!key || !form_tag || !prop_tag)
	{
		return 0;
	}

	key->form = *form_tag;
	key->prop = *prop_tag;

	return 1;
}

char IFF_Chunk_Key_Deconstruct
(
	struct IFF_Chunk_Key *key
)
{
	if (!key)
	{
	    return 0;
	}

    return 1;
}

char IFF_Chunk_Key_Release
(
	struct IFF_Chunk_Key *key
)
{
	if (key)
	{
		IFF_Chunk_Key_Deconstruct(key);
		free(key);
	}

	return 1;
}

char IFF_Chunk_Key_Hash
(
    void *key
    , VPS_TYPE_SIZE *key_hash
)
{
    if (!key || !key_hash)
    {
        return 0;
    }

    const struct IFF_Chunk_Key *k = key;
    VPS_TYPE_SIZE form_hash = 0;
    VPS_TYPE_SIZE prop_hash = 0;

    if
    (
        !IFF_Tag_Hash
        (
            &k->form
            , &form_hash
        )
    )
    {
        return 0;
    }

    if
    (
        !IFF_Tag_Hash
        (
            &k->prop
            , &prop_hash
        )
    )
    {
        return 0;
    }

    // Combine the two hashes. A simple XOR is usually sufficient.
    *key_hash = form_hash ^ prop_hash;

    return 1;
}

/**
 * @brief Compares two chunk keys by hierarchically comparing their constituent tags.
 */
char IFF_Chunk_Key_Compare
(
    void *key_1
    , void *key_2
    , VPS_TYPE_16S *ordering
)
{
    if (!key_1 || !key_2 || !ordering)
    {
        return 0;
    }

    const struct IFF_Chunk_Key *k1 = key_1;
    const struct IFF_Chunk_Key *k2 = key_2;

    // 1. Compare the form tags.
    if
    (
        !IFF_Tag_Compare
        (
            &k1->form
            , &k2->form
            , ordering
        )
    )
    {
        return 0;
    }

    // 2. If the form tags are equal, compare the prop tags.
    if (*ordering == 0)
    {
        if
        (
            !IFF_Tag_Compare
            (
                &k1->prop
                , &k2->prop
                , ordering
            )
        )
        {
            return 0;
        }
    }

    return 1;
}

char IFF_Chunk_Key_Clone
(
	struct IFF_Chunk_Key *key,
	struct IFF_Chunk_Key **clone
)
{
	if (!key || !clone)
	{
		return 0;
	}

	if (!IFF_Chunk_Key_Allocate(clone))
	{
		return 0;
	}

	// IFF_Chunk_Key is a struct of value-types only, thus we can by-value copy
	**clone = *key;

	return  1;
}
