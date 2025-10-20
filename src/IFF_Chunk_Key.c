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
	const unsigned char *raw_form_tag,
	const unsigned char *raw_prop_tag,
	VPS_TYPE_8U raw_tag_size
)
{
	if (!key || !raw_form_tag || !raw_prop_tag)
	{
		return 0;
	}

	// Construct the composite key from the raw tag data.
	// If either fails, the whole construction fails.
	return IFF_Tag_Construct(&key->form, raw_form_tag, raw_tag_size, IFF_TAG_TYPE_TAG) &&
	       IFF_Tag_Construct(&key->prop, raw_prop_tag, raw_tag_size, IFF_TAG_TYPE_TAG);
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