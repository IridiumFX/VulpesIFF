#include <stdlib.h>
#include <IFF/IFF_FormDecoder.h>

IFF_TYPE_RESULT IFF_FormDecoder_Allocate(struct IFF_FormDecoder **item)
{
    if (!item) return IFF_FAIL;
    *item = calloc(1, sizeof(struct IFF_FormDecoder));
    if (!*item) return IFF_FAIL;

    return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormDecoder_Construct(
    struct IFF_FormDecoder *item,
    IFF_TYPE_RESULT (*begin_decode)(struct IFF_Parser_State*, void**),
    IFF_TYPE_RESULT (*process_chunk)(struct IFF_Parser_State*, void*, struct IFF_Tag*, struct IFF_ContextualData*),
    IFF_TYPE_RESULT (*process_nested_form)(struct IFF_Parser_State*, void*, struct IFF_Tag*, void*),
    IFF_TYPE_RESULT (*end_decode)(struct IFF_Parser_State*, void*, void**)
)
{
    if (!item) return IFF_FAIL;
    item->begin_decode = begin_decode;
    item->process_chunk = process_chunk;
    item->process_nested_form = process_nested_form;
    item->end_decode = end_decode;
    return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormDecoder_Deconstruct(struct IFF_FormDecoder *item)
{
    if (!item) return IFF_FAIL;
    item->begin_decode = 0;
    item->process_chunk = 0;
    item->process_nested_form = 0;
    item->end_decode = 0;
    item->enter_container = 0;
    item->leave_container = 0;
    return IFF_OK;
}

IFF_TYPE_RESULT IFF_FormDecoder_Release(struct IFF_FormDecoder *item)
{
    if (item)
    {
        IFF_FormDecoder_Deconstruct(item);
        free(item);
    }
    return IFF_OK;
}


// --- VulpesCore boundary adapter ---

VPS_TYPE_RESULT IFF_FormDecoder_VPS_Release
(
	void *item
)
{
	return IFF_FormDecoder_Release(item);
}
