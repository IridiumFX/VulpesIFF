#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"

/*
 * File-transport round-trips: every other suite runs the write stack in
 * memory mode (CreateToData/CreateFromData). These tests push real bytes
 * through file descriptors on both sides — the StreamWriter/StreamReader
 * transport underneath the pumps.
 */

static int success_count = 0;
static int failure_count = 0;

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf; d.size = size; d.limit = size;
	return d;
}

/**
 * F1: file_blobbed_roundtrip
 *
 * Generate a blobbed FORM with one chunk through a file descriptor, then
 * parse the file back through another descriptor.
 */
static char test_file_blobbed_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	int write_handle = -1;
	int read_handle = -1;
	char result = 0;

	unsigned char data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	struct IFF_Header header;
	struct IFF_Tag form_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data wrap;

	const char *path = "iff_test_file_blobbed.iff";

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	IFF_Tag_Construct(&form_tag, (const unsigned char *)"TSTF", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	// --- Write through a file descriptor ---
	write_handle = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	TEST_ASSERT(write_handle >= 0);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Create(gen_factory, write_handle, &gen)) goto cleanup;

	TEST_ASSERT(IFF_Generator_WriteHeader(gen, &header));
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &form_tag));
	TEST_ASSERT(IFF_Generator_WriteChunk(gen, &body_tag, &wrap));
	TEST_ASSERT(IFF_Generator_EndForm(gen));
	TEST_ASSERT(IFF_Generator_Flush(gen));

	IFF_Generator_Release(gen);
	gen = 0;
	close(write_handle);
	write_handle = -1;

	// --- Read back through a file descriptor ---
	read_handle = open(path, O_RDONLY | O_BINARY);
	TEST_ASSERT(read_handle >= 0);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Create(parse_factory, read_handle, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	if (write_handle >= 0) close(write_handle);
	if (read_handle >= 0) close(read_handle);
	remove(path);

	return result;
}

/**
 * F2: file_progressive_sharded_roundtrip
 *
 * Progressive mode with SHARDING through file descriptors: a chunk split
 * across '    ' continuation directives must parse to completion.
 */
static char test_file_progressive_sharded_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	int write_handle = -1;
	int read_handle = -1;
	char result = 0;

	unsigned char data[64];
	struct IFF_Header header;
	struct IFF_Tag form_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data piece;
	VPS_TYPE_SIZE i;

	const char *path = "iff_test_file_sharded.iff";

	for (i = 0; i < sizeof(data); ++i)
	{
		data[i] = (unsigned char)i;
	}

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&form_tag, (const unsigned char *)"TSTF", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	// --- Write through a file descriptor ---
	write_handle = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	TEST_ASSERT(write_handle >= 0);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Create(gen_factory, write_handle, &gen)) goto cleanup;

	TEST_ASSERT(IFF_Generator_WriteHeader(gen, &header));
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &form_tag));

	// First 16 bytes in the chunk itself, the rest in three shards.
	piece = PRIVATE_Wrap(data, 16);
	TEST_ASSERT(IFF_Generator_WriteChunk(gen, &body_tag, &piece));

	for (i = 16; i < sizeof(data); i += 16)
	{
		piece = PRIVATE_Wrap(data + i, 16);
		TEST_ASSERT(IFF_Generator_WriteShard(gen, &piece));
	}

	TEST_ASSERT(IFF_Generator_EndForm(gen));
	TEST_ASSERT(IFF_Generator_Flush(gen));

	IFF_Generator_Release(gen);
	gen = 0;
	close(write_handle);
	write_handle = -1;

	// --- Read back through a file descriptor ---
	read_handle = open(path, O_RDONLY | O_BINARY);
	TEST_ASSERT(read_handle >= 0);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Create(parse_factory, read_handle, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	if (write_handle >= 0) close(write_handle);
	if (read_handle >= 0) close(read_handle);
	remove(path);

	return result;
}

void test_suite_file_roundtrip(void)
{
	success_count = 0;
	failure_count = 0;

	RUN_TEST(test_file_blobbed_roundtrip);
	RUN_TEST(test_file_progressive_sharded_roundtrip);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
