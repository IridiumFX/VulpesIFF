#include <stdlib.h>

#include <IFF/IFF_ReaderFrame.h>

IFF_TYPE_RESULT IFF_ReaderFrame_Allocate
(
	struct IFF_ReaderFrame **item
)
{
	struct IFF_ReaderFrame *frame;

	if (!item)
	{
		return IFF_FAIL;
	}

	frame = calloc(1, sizeof(struct IFF_ReaderFrame));
	if (!frame)
	{
		*item = 0;
		return IFF_FAIL;
	}

	*item = frame;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ReaderFrame_Construct
(
	struct IFF_ReaderFrame *item
	, struct IFF_Reader *reader
	, int file_handle
	, char iff85_locked
	, union IFF_Header_Flags flags
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	item->reader = reader;
	item->file_handle = file_handle;
	item->iff85_locked = iff85_locked;
	item->flags = flags;

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ReaderFrame_Deconstruct
(
	struct IFF_ReaderFrame *item
)
{
	if (!item)
	{
		return IFF_FAIL;
	}

	// No-op: does NOT release reader or close handle.
	// Ownership transfers on pop.

	return IFF_OK;
}

IFF_TYPE_RESULT IFF_ReaderFrame_Release
(
	struct IFF_ReaderFrame *item
)
{
	if (item)
	{
		IFF_ReaderFrame_Deconstruct(item);
		free(item);
	}

	return IFF_OK;
}


// --- VulpesCore boundary adapter ---

char IFF_ReaderFrame_VPS_Release
(
	void *item
)
{
	return IFF_ReaderFrame_Release(item) == IFF_OK;
}
