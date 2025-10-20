struct IFF_Chunk
{
	struct IFF_Tag	tag;
	VPS_TYPE_SIZE	size;
	void *data;
};