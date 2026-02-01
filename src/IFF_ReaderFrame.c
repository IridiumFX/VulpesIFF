#include <stdlib.h>

#include <IFF/IFF_ReaderFrame.h>

char IFF_ReaderFrame_Allocate
(
	struct IFF_ReaderFrame **item
)
{
	struct IFF_ReaderFrame *frame;

	if (!item)
	{
		return 0;
	}

	frame = calloc(1, sizeof(struct IFF_ReaderFrame));
	if (!frame)
	{
		*item = 0;
		return 0;
	}

	*item = frame;

	return 1;
}

char IFF_ReaderFrame_Construct
(
	struct IFF_ReaderFrame *item
	, struct IFF_Reader *reader
	, int file_handle
	, char iff85_locked
)
{
	if (!item)
	{
		return 0;
	}

	item->reader = reader;
	item->file_handle = file_handle;
	item->iff85_locked = iff85_locked;

	return 1;
}

char IFF_ReaderFrame_Deconstruct
(
	struct IFF_ReaderFrame *item
)
{
	if (!item)
	{
		return 0;
	}

	// No-op: does NOT release reader or close handle.
	// Ownership transfers on pop.

	return 1;
}

char IFF_ReaderFrame_Release
(
	struct IFF_ReaderFrame *item
)
{
	if (item)
	{
		IFF_ReaderFrame_Deconstruct(item);
		free(item);
	}

	return 1;
}
