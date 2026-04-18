#include <stdlib.h>
#include <IFF/IFF_FormDecoder.h>

char IFF_FormDecoder_Allocate(struct IFF_FormDecoder **item)
{
    if (!item) return 0;
    *item = calloc(1, sizeof(struct IFF_FormDecoder));
    return *item != 0;
}

char IFF_FormDecoder_Construct(
    struct IFF_FormDecoder *item,
    char (*begin_decode)(struct IFF_Parser_State*, void**),
    char (*process_chunk)(struct IFF_Parser_State*, void*, struct IFF_Tag*, struct IFF_ContextualData*),
    char (*process_nested_form)(struct IFF_Parser_State*, void*, struct IFF_Tag*, void*),
    char (*end_decode)(struct IFF_Parser_State*, void*, void**)
)
{
    if (!item) return 0;
    item->begin_decode = begin_decode;
    item->process_chunk = process_chunk;
    item->process_nested_form = process_nested_form;
    item->end_decode = end_decode;
    return 1;
}

char IFF_FormDecoder_Deconstruct(struct IFF_FormDecoder *item)
{
    if (!item) return 0;
    item->begin_decode = 0;
    item->process_chunk = 0;
    item->process_nested_form = 0;
    item->end_decode = 0;
    item->enter_container = 0;
    item->leave_container = 0;
    return 1;
}

char IFF_FormDecoder_Release(struct IFF_FormDecoder *item)
{
    if (item)
    {
        IFF_FormDecoder_Deconstruct(item);
        free(item);
    }
    return 1;
}
