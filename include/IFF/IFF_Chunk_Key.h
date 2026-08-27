#pragma once

#include <IFF/IFF_Result.h>

struct IFF_Chunk_Key
{
	struct IFF_Tag form;
	struct IFF_Tag prop;
};

IFF_TYPE_RESULT IFF_Chunk_Key_Allocate
(
	struct IFF_Chunk_Key **key
);

IFF_TYPE_RESULT IFF_Chunk_Key_Construct
(
	struct IFF_Chunk_Key *key,
	const struct IFF_Tag* form_tag,
	const struct IFF_Tag* prop_tag
);

IFF_TYPE_RESULT IFF_Chunk_Key_Deconstruct
(
	struct IFF_Chunk_Key *key
);

IFF_TYPE_RESULT IFF_Chunk_Key_Release
(
	struct IFF_Chunk_Key *key
);

IFF_TYPE_RESULT IFF_Chunk_Key_Hash
(
	void *key
	, VPS_TYPE_SIZE *key_hash
);

IFF_TYPE_RESULT IFF_Chunk_Key_Compare
(
	void *key_1
	, void *key_2
	, VPS_TYPE_16S *ordering
);

IFF_TYPE_RESULT IFF_Chunk_Key_Clone
(
	struct IFF_Chunk_Key *key,
	struct IFF_Chunk_Key **clone
);

/*
 * --- VulpesCore boundary adapters ---
 *
 * VulpesCore containers expect the boolean convention (1 = success) and do
 * check the result of hash and compare, so these shims translate polarity.
 * Register these with VPS_Dictionary_Construct rather than casting the
 * functions above, which would invert every lookup.
 */

char IFF_Chunk_Key_VPS_Hash
(
	void *key
	, VPS_TYPE_SIZE *key_hash
);

char IFF_Chunk_Key_VPS_Compare
(
	void *key_1
	, void *key_2
	, VPS_TYPE_16S *ordering
);

char IFF_Chunk_Key_VPS_Release
(
	void *key
);
