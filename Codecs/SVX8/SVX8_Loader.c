#include <stdio.h>
#include <stdlib.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "SVX8/SVX8_Types.h"
#include "SVX8/SVX8_Codec.h"
#include "SVX8/SVX8_Loader.h"

struct SVX8_Result* VPS_SVX8_LoadFromFile(const char* filepath)
{
	if (!filepath) return NULL;

	FILE* f = fopen(filepath, "rb");
	if (!f) return NULL;

	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (file_size <= 0) { fclose(f); return NULL; }

	struct VPS_Data* data = NULL;
	VPS_Data_Allocate(&data, (VPS_TYPE_SIZE)file_size, (VPS_TYPE_SIZE)file_size);
	if (!data) { fclose(f); return NULL; }

	fread(data->bytes, 1, (size_t)file_size, f);
	fclose(f);

	struct IFF_Parser_Factory* factory = NULL;
	IFF_Parser_Factory_Allocate(&factory);
	IFF_Parser_Factory_Construct(factory);

	if (!SVX8_RegisterDecoders(factory))
	{
		IFF_Parser_Factory_Release(factory);
		VPS_Data_Release(data);
		return NULL;
	}

	struct IFF_Parser* parser = NULL;
	if (!IFF_Parser_Factory_CreateFromData(factory, data, &parser))
	{
		IFF_Parser_Factory_Release(factory);
		VPS_Data_Release(data);
		return NULL;
	}

	if (!IFF_Parser_Scan(parser))
	{
		IFF_Parser_Release(parser);
		IFF_Parser_Factory_Release(factory);
		VPS_Data_Release(data);
		return NULL;
	}

	void* entity = parser->session->final_entity;
	parser->session->final_entity = NULL;

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	VPS_Data_Release(data);

	struct SVX8_Result* result = (struct SVX8_Result*)entity;
	if (result)
		printf("8SVX: Loaded '%s' (%u Hz, %llu samples)\n", filepath,
		       result->vhdr.samplesPerSec, (unsigned long long)result->samples->size);

	return result;
}
