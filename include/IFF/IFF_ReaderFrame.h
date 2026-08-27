#pragma once

#include <IFF/IFF_Result.h>
#include <IFF/IFF_Header.h>

struct IFF_Reader;

struct IFF_ReaderFrame
{
	struct IFF_Reader *reader;
	int file_handle;
	char iff85_locked;

	// Global-scope flags of the including stream. Segments are
	// self-contained: the included one bootstraps from defaults, and the
	// caller's configuration is restored on resumption (spec Section 6.2).
	union IFF_Header_Flags flags;
};

IFF_TYPE_RESULT IFF_ReaderFrame_Allocate
(
	struct IFF_ReaderFrame **item
);

IFF_TYPE_RESULT IFF_ReaderFrame_Construct
(
	struct IFF_ReaderFrame *item
	, struct IFF_Reader *reader
	, int file_handle
	, char iff85_locked
	, union IFF_Header_Flags flags
);

IFF_TYPE_RESULT IFF_ReaderFrame_Deconstruct
(
	struct IFF_ReaderFrame *item
);

IFF_TYPE_RESULT IFF_ReaderFrame_Release
(
	struct IFF_ReaderFrame *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * VulpesCore containers expect the boolean convention (1 = success).
 * Register this shim as the release hook rather than casting the function
 * above, whose polarity is inverted.
 */

char IFF_ReaderFrame_VPS_Release
(
	void *item
);
