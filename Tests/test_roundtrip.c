#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_DataTap.h>
#include <IFF/IFF_WriteTap.h>
#include <IFF/IFF_Reader.h>
#include <IFF/IFF_Writer.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestChecksumAlgorithm.h"
#include "IFF_TestEncoders.h"

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf; d.size = size; d.limit = size;
	return d;
}

static struct VPS_Set *PRIVATE_CreateAlgoSet(const char *id, VPS_TYPE_SIZE id_len)
{
	struct VPS_Set *s = 0;
	struct VPS_Data *d = 0;

	if (!VPS_Data_Allocate(&d, id_len, id_len)) return 0;
	if (!VPS_Data_Construct(d)) { VPS_Data_Release(d); return 0; }
	memcpy(d->bytes, id, id_len);
	d->limit = id_len;

	if (!VPS_Set_Allocate(&s, 7)) { VPS_Data_Release(d); return 0; }
	if (!VPS_Set_Construct(s, VPS_Hash_Utils_Data, VPS_Compare_Utils_Data,
		(char (*)(void *))VPS_Data_Release, 2, 75, 8))
	{ VPS_Set_Release(s); VPS_Data_Release(d); return 0; }

	if (!VPS_Set_Add(s, d)) { VPS_Set_Release(s); return 0; }
	return s;
}

/** W88: roundtrip_nested_containers — CAT > LIST > FORM with PROP */
static char test_roundtrip_nested_containers(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd[10] = {0};
	unsigned char body[4] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, cat, list, bmhd_t, body_t;
	struct VPS_Data bw, dw;

	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_t, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_t, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	bw = PRIVATE_Wrap(bmhd, 10);
	dw = PRIVATE_Wrap(body, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginCat(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginList(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_t, &bw)) goto cleanup;
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_t, &dw)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_EndCat(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W89: roundtrip_all_container_types — FORM, LIST+PROP, CAT in sequence */
static char test_roundtrip_all_container_types(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;

	// FORM
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// LIST with PROP
	if (!IFF_Generator_BeginList(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	// CAT
	if (!IFF_Generator_BeginCat(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W90: roundtrip_checksum — CHK..SUM around chunk, verify on parse */
static char test_roundtrip_checksum(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char data[10] = {0x42};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;
	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(algo_set);
	return result;
}

/** W91: roundtrip_16bit_le */
static char test_roundtrip_16bit_le(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;
	h.flags.as_fields.sizing = IFF_Header_Sizing_16;
	h.flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W92: roundtrip_64bit_8tag */
static char test_roundtrip_64bit_8tag(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;
	h.flags.as_fields.sizing = IFF_Header_Sizing_64;
	h.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W93: roundtrip_no_padding_odd_chunk */
static char test_roundtrip_no_padding_odd_chunk(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;
	h.flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 5);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W94: roundtrip_sharding */
static char test_roundtrip_sharding(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char chunk[8] = {0};
	unsigned char shard[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data cw, sw;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;
	h.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	cw = PRIVATE_Wrap(chunk, 8);
	sw = PRIVATE_Wrap(shard, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &cw)) goto cleanup;
	if (!IFF_Generator_WriteShard(gen, &sw)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W95: roundtrip_multiple_top_forms */
static char test_roundtrip_multiple_top_forms(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, svx, body;
	struct VPS_Data wrap;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&svx, (const unsigned char *)"8SVX", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &svx)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W96: roundtrip_def_ref — DEF + FORM + REF(optional, no resolver) */
static char test_roundtrip_def_ref(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Data *def_id = 0;
	struct VPS_Data *ref_id = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;
	const struct VPS_Data *ids[1];

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	if (!VPS_Data_Allocate(&def_id, 4, 4)) goto cleanup;
	memcpy(def_id->bytes, "SEG1", 4);
	if (!VPS_Data_Allocate(&ref_id, 4, 4)) goto cleanup;
	memcpy(ref_id->bytes, "SEG1", 4);
	ids[0] = ref_id;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_WriteDEF(gen, def_id)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_WriteREF(gen, 1, ids)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	// No resolver registered — REF silently consumed.
	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Data_Release(def_id);
	VPS_Data_Release(ref_id);
	return result;
}

/** W97: roundtrip_ver_rev */
static char test_roundtrip_ver_rev(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char ver[8] = {0};
	unsigned char rev[4] = {0};
	unsigned char data[4] = {0};
	struct IFF_Header h;
	struct IFF_Tag ilbm, body;
	struct VPS_Data vw, rw, dw;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	vw = PRIVATE_Wrap(ver, 8);
	rw = PRIVATE_Wrap(rev, 4);
	dw = PRIVATE_Wrap(data, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_WriteVER(gen, &vw)) goto cleanup;
	if (!IFF_Generator_WriteREV(gen, &rw)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &dw)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W98: roundtrip_encoder_progressive_checksum */
static char test_roundtrip_encoder_progressive_checksum(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormEncoder *form_enc = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header h;
	struct IFF_Tag ilbm;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	struct TestSourceEntity entity;
	entity.chunk_count = 1;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_data;
	entity.chunks[0].size = 10;

	h.version = IFF_Header_Version_2025; h.revision = 0; h.flags.as_int = 0;
	h.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_TestEncoders_CreateFormEncoder(&form_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gf, &ilbm, form_enc)) goto cleanup;
	form_enc = 0;

	if (!IFF_Generator_WriteHeader(gen, &h)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_EncodeForm(gen, &ilbm, &entity)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;
cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	IFF_FormEncoder_Release(form_enc);
	VPS_Set_Release(algo_set);
	return result;
}

void test_suite_roundtrip(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_roundtrip_nested_containers);
	RUN_TEST(test_roundtrip_all_container_types);
	RUN_TEST(test_roundtrip_checksum);
	RUN_TEST(test_roundtrip_16bit_le);
	RUN_TEST(test_roundtrip_64bit_8tag);
	RUN_TEST(test_roundtrip_no_padding_odd_chunk);
	RUN_TEST(test_roundtrip_sharding);
	RUN_TEST(test_roundtrip_multiple_top_forms);
	RUN_TEST(test_roundtrip_def_ref);
	RUN_TEST(test_roundtrip_ver_rev);
	RUN_TEST(test_roundtrip_encoder_progressive_checksum);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
