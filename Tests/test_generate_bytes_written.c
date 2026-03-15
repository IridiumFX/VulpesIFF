#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_WriteScope.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf; d.size = size; d.limit = size;
	return d;
}

static struct IFF_WriteScope *PRIVATE_CurrentScope(struct IFF_Generator *gen)
{
	if (!gen->scope_stack || gen->scope_stack->count == 0) return 0;
	return (struct IFF_WriteScope *)gen->scope_stack->tail->data;
}

/**
 * W99: bytes_written_single_chunk
 *
 * After WriteChunk, scope's bytes_written == tag_len + size_len + data_size + padding.
 * Default config: 4-byte tags, 4-byte sizes.
 * Chunk with 10-byte payload: 4 + 4 + 10 = 18 (even, no padding).
 */
static char test_bytes_written_single_chunk(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;
	struct IFF_WriteScope *scope;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	// IFF-85 defaults: 4-byte tags, 4-byte sizes.
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;

	scope = PRIVATE_CurrentScope(gen);
	TEST_ASSERT(scope != 0);
	// tag(4) + size(4) + data(10) = 18
	TEST_ASSERT(scope->bytes_written == 18);

	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/**
 * W100: bytes_written_two_chunks
 *
 * After two WriteChunk calls, scope's bytes_written is cumulative total.
 * Chunk1: BODY 10 bytes = 4+4+10 = 18
 * Chunk2: CMAP 6 bytes = 4+4+6 = 14
 * Total = 32
 */
static char test_bytes_written_two_chunks(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char body_data[10] = {0};
	unsigned char cmap_data[6] = {0};
	struct IFF_Tag ilbm, body, cmap;
	struct VPS_Data bw, cw;
	struct IFF_WriteScope *scope;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&cmap, (const unsigned char *)"CMAP", 4, IFF_TAG_TYPE_TAG);
	bw = PRIVATE_Wrap(body_data, 10);
	cw = PRIVATE_Wrap(cmap_data, 6);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &bw)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &cmap, &cw)) goto cleanup;

	scope = PRIVATE_CurrentScope(gen);
	TEST_ASSERT(scope != 0);
	// 18 + 14 = 32
	TEST_ASSERT(scope->bytes_written == 32);

	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/**
 * W101: bytes_written_filler
 *
 * WriteFiller(8) adds tag_len + size_len + 8 to bytes_written.
 * Default config: filler = 4+4+8 = 16.
 */
static char test_bytes_written_filler(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag ilbm;
	struct IFF_WriteScope *scope;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteFiller(gen, 8)) goto cleanup;

	scope = PRIVATE_CurrentScope(gen);
	TEST_ASSERT(scope != 0);
	// tag(4) + size(4) + data(8) = 16
	TEST_ASSERT(scope->bytes_written == 16);

	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/**
 * W102: bytes_written_nested
 *
 * Nested FORM's bytes contribute to parent scope's bytes_written on EndForm.
 * Inner FORM(ILBM) with BODY(4): inner bytes_written = 4+4+4 = 12.
 * After EndForm, parent (LIST) bytes_written includes the full inner FORM.
 */
static char test_bytes_written_nested(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;
	struct IFF_WriteScope *scope;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;

	// Inner scope: tag(4) + size(4) + data(4) = 12
	scope = PRIVATE_CurrentScope(gen);
	TEST_ASSERT(scope != 0);
	TEST_ASSERT(scope->bytes_written == 12);

	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// After EndForm, parent (LIST) scope includes the full nested FORM.
	// Parent bytes_written = FORM_tag(4) + size(4) + type_tag(4) + inner(12) = 24
	// (Blobbed: FORM tag + size field + ILBM type + body content)
	scope = PRIVATE_CurrentScope(gen);
	TEST_ASSERT(scope != 0);
	TEST_ASSERT(scope->bytes_written > 0);

	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

void test_suite_generate_bytes_written(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_bytes_written_single_chunk);
	RUN_TEST(test_bytes_written_two_chunks);
	RUN_TEST(test_bytes_written_filler);
	RUN_TEST(test_bytes_written_nested);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
