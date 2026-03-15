#include <stdio.h>
#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "ILBM/ILBM_Types.h"
#include "ILBM/ILBM_Codec.h"
#include "ILBM/ILBM_Loader.h"

struct ILBM_Result* VPS_ILBM_LoadFromData(const struct VPS_Data* data)
{
	if (!data) return NULL;

	struct IFF_Parser_Factory* factory = NULL;
	IFF_Parser_Factory_Allocate(&factory);
	IFF_Parser_Factory_Construct(factory);

	if (!ILBM_RegisterDecoders(factory))
	{
		IFF_Parser_Factory_Release(factory);
		return NULL;
	}

	struct IFF_Parser* parser = NULL;
	if (!IFF_Parser_Factory_CreateFromData(factory, data, &parser))
	{
		IFF_Parser_Factory_Release(factory);
		return NULL;
	}

	if (!IFF_Parser_Scan(parser))
	{
		fprintf(stderr, "ILBM: Parse failed\n");
		IFF_Parser_Release(parser);
		IFF_Parser_Factory_Release(factory);
		return NULL;
	}

	void* entity = parser->session->final_entity;
	parser->session->final_entity = NULL; /* Take ownership. */

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);

	return (struct ILBM_Result*)entity;
}

struct ILBM_Result* VPS_ILBM_LoadFromFile(const char* filepath)
{
	if (!filepath) return NULL;

	FILE* f = fopen(filepath, "rb");
	if (!f)
	{
		fprintf(stderr, "ILBM: Cannot open '%s'\n", filepath);
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (file_size <= 0)
	{
		fclose(f);
		return NULL;
	}

	struct VPS_Data* data = NULL;
	VPS_Data_Allocate(&data, (VPS_TYPE_SIZE)file_size, (VPS_TYPE_SIZE)file_size);
	if (!data) { fclose(f); return NULL; }

	fread(data->bytes, 1, (size_t)file_size, f);
	fclose(f);

	struct ILBM_Result* result = VPS_ILBM_LoadFromData(data);
	VPS_Data_Release(data);

	if (result)
		printf("ILBM: Loaded '%s' (%ux%u)\n", filepath, result->width, result->height);

	return result;
}
