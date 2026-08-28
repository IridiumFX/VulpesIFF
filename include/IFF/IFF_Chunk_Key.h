#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

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
 * VulpesCore and VulpesIFF now report the same convention, so these shims
 * no longer translate anything: they exist only to present the typed
 * functions above through the void * a VulpesCore callback slot expects.
 */



VPS_TYPE_RESULT IFF_Chunk_Key_VPS_Release
(
	void *key
);
