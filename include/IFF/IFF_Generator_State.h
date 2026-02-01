/**
 * @brief Encoder-facing view into the generator's state.
 * @details Mirrors IFF_Parser_State for the read-side. Passed to
 *          FormEncoder and ChunkEncoder callbacks so they can access
 *          configuration without coupling to generator internals.
 */
struct IFF_Generator_State
{
	struct IFF_Generator *generator;
	union IFF_Header_Flags flags;
};
