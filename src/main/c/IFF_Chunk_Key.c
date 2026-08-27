#include <string.h>
#include <stdlib.h>
#include <vulpes/VPS_Types.h>
#include <IFF/IFF_Result.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>

IFF_TYPE_RESULT IFF_Chunk_Key_Allocate
(
	struct IFF_Chunk_Key **key
)
{
	if (!key)
	{
	    return IFF_FAIL;
	}

	*key = calloc(1, sizeof(struct IFF_Chunk_Key));
	if (!*key)
	{
		return IFF_FAIL;
	}

    return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Key_Construct
(
	struct IFF_Chunk_Key *key,
	const struct IFF_Tag* form_tag,
	const struct IFF_Tag* prop_tag
)
{
	if (!key || !form_tag || !prop_tag)
	{
		return IFF_FAIL;
	}

	key->form = *form_tag;
	key->prop = *prop_tag;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Key_Deconstruct
(
	struct IFF_Chunk_Key *key
)
{
	if (!key)
	{
	    return IFF_FAIL;
	}

    return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Key_Release
(
	struct IFF_Chunk_Key *key
)
{
	if (key)
	{
		IFF_Chunk_Key_Deconstruct(key);
		free(key);
	}

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Key_Hash
(
    void *key
    , VPS_TYPE_SIZE *key_hash
)
{
    IFF_TYPE_RESULT result;

    if (!key || !key_hash)
    {
        return IFF_FAIL;
    }

    const struct IFF_Chunk_Key *k = key;
    VPS_TYPE_SIZE form_hash = 0;
    VPS_TYPE_SIZE prop_hash = 0;

    result = IFF_Tag_Hash
    (
        &k->form
        , &form_hash
    );
    if (result)
    {
        return result;
    }

    result = IFF_Tag_Hash
    (
        &k->prop
        , &prop_hash
    );
    if (result)
    {
        return result;
    }

    // Combine the two hashes asymmetrically: a plain XOR would collide
    // (A,B) with (B,A) and hash every (X,X) key to the same bucket.
    *key_hash = (form_hash * 0x100000001B3ULL) ^ prop_hash;

    return IFF_OK;
}

/**
 * @brief Compares two chunk keys by hierarchically comparing their constituent tags.
 */
IFF_TYPE_RESULT IFF_Chunk_Key_Compare
(
    void *key_1
    , void *key_2
    , VPS_TYPE_16S *ordering
)
{
    IFF_TYPE_RESULT result;

    if (!key_1 || !key_2 || !ordering)
    {
        return IFF_FAIL;
    }

    const struct IFF_Chunk_Key *k1 = key_1;
    const struct IFF_Chunk_Key *k2 = key_2;

    // 1. Compare the form tags.
    result = IFF_Tag_Compare
    (
        &k1->form
        , &k2->form
        , ordering
    );
    if (result)
    {
        return result;
    }

    // 2. If the form tags are equal, compare the prop tags.
    if (*ordering == 0)
    {
        result = IFF_Tag_Compare
        (
            &k1->prop
            , &k2->prop
            , ordering
        );
        if (result)
        {
            return result;
        }
    }

    return IFF_OK;
}

IFF_TYPE_RESULT IFF_Chunk_Key_Clone
(
	struct IFF_Chunk_Key *key,
	struct IFF_Chunk_Key **clone
)
{
	IFF_TYPE_RESULT result;

	if (!key || !clone)
	{
		return IFF_FAIL;
	}

	result = IFF_Chunk_Key_Allocate(clone);
	if (result)
	{
		return result;
	}

	// IFF_Chunk_Key is a struct of value-types only, thus we can by-value copy
	**clone = *key;

	return IFF_OK;
}


// --- VulpesCore boundary adapters ---

char IFF_Chunk_Key_VPS_Hash
(
	void *key
	, VPS_TYPE_SIZE *key_hash
)
{
	return IFF_Chunk_Key_Hash(key, key_hash) == IFF_OK;
}

char IFF_Chunk_Key_VPS_Compare
(
	void *key_1
	, void *key_2
	, VPS_TYPE_16S *ordering
)
{
	return IFF_Chunk_Key_Compare(key_1, key_2, ordering) == IFF_OK;
}

char IFF_Chunk_Key_VPS_Release
(
	void *key
)
{
	return IFF_Chunk_Key_Release(key) == IFF_OK;
}
