VulpesIFF Integration Guide
============================

### Using the VulpesIFF Reference Implementation

**Version**: 1.0
**Companion to**: [IFF-2025 Implementor's Guide](../IFF-2025/Docs/IFF-2025-implementors-guide.md)
**Language**: C23 (MinGW GCC 13.1)
**License**: MIT

---

## How to Read This Guide

This guide covers VulpesIFF-specific conventions, architecture, and API
patterns. For IFF-2025 format concepts (tag systems, container parsing, checksum
verification, segmentation), see the
[IFF-2025 Implementor's Guide](../IFF-2025/Docs/IFF-2025-implementors-guide.md).

---

# Part I: Architecture & Conventions

## Section 1 — Object Lifecycle Pattern

Every VulpesIFF type follows a four-phase lifecycle:

```
Allocate(type) -> pointer     // calloc, returns zeroed memory
Construct(pointer, args)      // Initialize fields, acquire resources
Deconstruct(pointer)          // Release owned resources, zero fields
Release(pointer)              // free the memory
```

Each phase returns `IFF_TYPE_RESULT`: `IFF_OK` (0) on success, a non-zero
failure line otherwise. See Section 2.

`Construct` must be called exactly once after `Allocate`. `Deconstruct` must be
called exactly once before `Release`. These are not reference-counted --- the
caller is responsible for ensuring correct pairing.

## Section 2 --- Return Convention

All functions return `IFF_TYPE_RESULT`, declared in `IFF/IFF_Result.h`:

```c
typedef unsigned long IFF_TYPE_RESULT;

#define IFF_OK    ((IFF_TYPE_RESULT)0)
#define IFF_FAIL  ((IFF_TYPE_RESULT)__LINE__)
```

- `IFF_OK` (0) = success.
- Any non-zero value = failure, and the value is the line inside VulpesIFF
  that raised it.

So a failing call tells you where it went wrong without a debugger:

```c
IFF_TYPE_RESULT result = IFF_Parser_Scan(parser);
if (result)
{
    printf("parse failed at IFF source line %lu\n", (unsigned long)result);
}
```

Note the polarity: this is the inverse of a boolean. `if (result)` means
*failure*. Code ported from the previous `char` convention must invert every
test, and the compiler cannot help you --- both types are integers.

### 2.1 Propagating a failure

When forwarding a failure from a nested call, return the value you received
rather than raising a fresh `IFF_FAIL`. The original line is the useful one;
overwriting it discards the root cause.

```c
result = IFF_Reader_ReadTag(reader, tag_sizing, &tag);
if (result)
{
    return result;          /* not: return IFF_FAIL; */
}
```

### 2.2 Crossing the VulpesCore boundary

VulpesCore reports `VPS_TYPE_RESULT` with the same polarity: `VPS_OK` (0) is
success. Both typedefs are `unsigned long`, so a `VPS_` result can be tested,
propagated and returned exactly like an `IFF_TYPE_RESULT` --- no bridging, no
conversion:

```c
IFF_TYPE_RESULT result = VPS_DataWriter_WriteBytes(dw, buf, len);
if (result)
{
    return result;
}
```

The two remain separate typedefs rather than one shared alias, because neither
framework includes the other's headers. VulpesCore is buildable on its own;
VulpesIFF simply agrees with it.

In the other direction, IFF functions registered into VulpesCore callback slots
still go through a `_VPS_` adapter --- `IFF_Tag_VPS_Hash` alongside
`IFF_Tag_Hash`, and so on. These no longer translate anything. They exist only
because a callback slot is declared over `void *` while the functions they wrap
take typed pointers:

```c
VPS_TYPE_RESULT IFF_Tag_VPS_Hash(void *key, VPS_TYPE_SIZE *key_hash)
{
    return IFF_Tag_Hash(key, key_hash);
}
```

Where a function already takes `void *` --- `IFF_Chunk_Key_Hash` and
`IFF_Chunk_Key_Compare` do --- it is registered directly and has no adapter.

### 2.3 What does not use this type

Predicates answer a question rather than report a status, and keep the plain
`char` boolean form (`1` = yes):

| Function                              | Question                          |
|---------------------------------------|-----------------------------------|
| `IFF_Parser_Session_IsActive`         | Is the session still consuming?   |
| `IFF_Parser_Session_IsBoundaryOpen`   | Does the scope still have room?   |
| `IFF_Reader_IsActive`                 | Are there bytes left to read?     |
| `IFF_Parser_Session_FindProp`         | Is a property registered?         |
| `IFF_Parser_State_FindProp`           | Is a property registered?         |

A `FindProp` miss is a normal outcome, not a fault, which is why it reports
found/not-found rather than a status:

```c
if (IFF_Parser_State_FindProp(state, &cmap_tag, &prop) && prop && prop->data)
{
    apply_palette(header, prop->data);
}
```

Boolean out-parameters are likewise unrelated to the return channel and stay
`char`: `out_done` on the encoder callbacks, `out_scope_ended` internally.

## Section 3 --- Naming Conventions

**Public API**: `IFF_TypeName_FunctionName` (e.g., `IFF_Parser_Scan`)

**Private statics**: `PRIVATE_IFF_TypeName_FunctionName` or
`IFF_TypeName_PRIVATE_FunctionName`

**Parameters**: One per line, comma-leading continuation:

```c
IFF_TYPE_RESULT IFF_Parser_Factory_RegisterChunkDecoder(
    struct IFF_Parser_Factory *item
    , const struct IFF_Chunk_Key* chunk_key
    , struct IFF_ChunkDecoder *decoder
);
```

## Section 4 --- VulpesCore Dependencies

VulpesIFF uses the VulpesCore library for foundational types:

| VulpesCore Type         | Purpose in IFF                                   |
|-------------------------|--------------------------------------------------|
| `VPS_Data`              | Raw byte buffer (owns memory)                    |
| `VPS_DataReader`        | Sequential read cursor over VPS_Data             |
| `VPS_DataWriter`        | Sequential write cursor over VPS_Data            |
| `VPS_StreamReader`      | Buffered file input                              |
| `VPS_StreamWriter`      | Buffered file output                             |
| `VPS_List`              | Dynamic array (used for scope stacks, span lists)|
| `VPS_Dictionary`        | Hash map (used for decoder/algorithm registries) |
| `VPS_ScopedDictionary`  | Dictionary with push/pop scoping                 |
| `VPS_Set`               | Unique string set (used for algorithm ID sets)   |
| `VPS_Endian`            | Byte-order conversion helpers                    |
| `VPS_Decoder`           | Content decoder interface (future use)           |

## Section 5 --- Build Toolchain

- **Language**: C23 (`-std=gnu2x`)
- **Compiler**: MinGW GCC 13.1
- **Build system**: CMake + Ninja
- **Products**: Static libraries (`VulpesCore`, `VulpesIFF`)

---

# Part II: Implementation Type Reference

## Section 6 --- Read Stack Types

| Type                     | Layer    | Fields / Purpose                                       |
|--------------------------|----------|--------------------------------------------------------|
| `IFF_DataPump`           | Layer 1  | `stream_reader`, `data_buffer`, `data_reader` --- Buffered I/O |
| `IFF_DataTap`            | Layer 2  | `pump`, `registered_algorithms`, `active_spans` --- Checksum middleware |
| `IFF_Reader`             | Layer 3  | `tap`, `content_decoders` --- Primitive interpretation   |
| `IFF_Scope`              | Context  | `flags`, `boundary`, `container_variant/type`, decoder state --- Per-container read context |
| `IFF_ReaderFrame`        | Stack    | `reader`, `file_handle`, `iff85_locked` --- Saved reader state for inclusion |
| `IFF_Parser_Session`     | State    | `scope_stack`, `current_scope`, `session_state`, `iff85_locked`, `parsing_resumed`, `props`, `final_entity` |
| `IFF_Parser_State`       | Facade   | `session` --- Decoder-facing view (exposes `FindProp`)  |
| `IFF_Parser`             | Layer 4  | `session`, `reader`, decoder dictionaries, `reader_stack`, `segment_resolver`, `strict_references` |
| `IFF_Parser_Factory`     | Builder  | `form_decoders`, `chunk_decoders`, `directive_processors` --- Constructs configured parsers |

## Section 7 --- Write Stack Types

| Type                     | Layer    | Fields / Purpose                                       |
|--------------------------|----------|--------------------------------------------------------|
| `IFF_WritePump`          | Layer 1  | `stream_writer` --- Raw output                          |
| `IFF_WriteTap`           | Layer 2  | `pump`, `registered_algorithms`, `active_spans` --- Checksum middleware |
| `IFF_Writer`             | Layer 3  | `tap`, `content_encoders` --- Primitive serialization    |
| `IFF_WriteScope`         | Context  | `flags`, `container_variant/type`, `accumulator`, `accumulator_writer`, `bytes_written`, encoder state |
| `IFF_Generator`          | Layer 4  | `writer`, `scope_stack`, `file_handle`, `flags`, `blobbed_spans`, encoder dictionaries |
| `IFF_Generator_State`    | Facade   | `generator`, `flags` --- Encoder-facing view             |
| `IFF_Generator_Factory`  | Builder  | `form_encoders`, `chunk_encoders` --- Constructs configured generators |

---

# Part III: Writing Decoders

## Section 8 --- ChunkDecoder

### 8.1 The ChunkDecoder Vtable

A `ChunkDecoder` converts raw chunk bytes into a structured application object.
It has three callbacks:

```c
struct IFF_ChunkDecoder {
    // Called when the first part of the chunk is encountered
    IFF_TYPE_RESULT (*begin_decode)(
        struct IFF_Parser_State *state
        , void **custom_state
    );

    // Called for each data fragment (once without sharding, multiple with)
    IFF_TYPE_RESULT (*process_shard)(
        struct IFF_Parser_State *state
        , void *custom_state
        , const struct VPS_Data *chunk_data
    );

    // Called after the final shard; produces the decoded object
    IFF_TYPE_RESULT (*end_decode)(
        struct IFF_Parser_State *state
        , void *custom_state
        , struct IFF_ContextualData **out
    );
};
```

### 8.2 Registration

Chunk decoders are registered with the parser factory using a composite key
that pairs the container type with the chunk tag:

```
// Register a BMHD decoder for ILBM forms
IFF_Chunk_Key key = { .container_type = ILBM_tag, .chunk_tag = BMHD_tag };
IFF_Parser_Factory_RegisterChunkDecoder(factory, &key, bmhd_decoder);
```

### 8.3 Example: Decoding a Bitmap Header

```
// State for accumulating shard data
struct BMHD_State {
    VPS_Data* accumulated;
};

IFF_TYPE_RESULT bmhd_begin(IFF_Parser_State *state, void **custom_state):
    allocate BMHD_State -> s
    if s == NULL:
        return IFF_FAIL
    s.accumulated = NULL
    *custom_state = s
    return IFF_OK

IFF_TYPE_RESULT bmhd_process_shard(IFF_Parser_State *state, void *cs, const VPS_Data *data):
    BMHD_State *s = cs
    if s.accumulated == NULL:
        s.accumulated = clone(data)
    else:
        append data to s.accumulated
    return IFF_OK

IFF_TYPE_RESULT bmhd_end(IFF_Parser_State *state, void *cs, IFF_ContextualData **out):
    BMHD_State *s = cs
    // Parse the raw bytes into a structured bitmap header
    BitmapHeader *header = parse_bmhd_bytes(s.accumulated)

    // Optionally look up shared properties
    IFF_ContextualData *cmap = NULL
    IFF_Parser_State_FindProp(state, &CMAP_tag, &cmap)
    if cmap != NULL:
        apply_palette(header, cmap.data)

    // Wrap result in IFF_ContextualData
    IFF_ContextualData_Allocate(out)
    IFF_ContextualData_Construct(*out, current_flags, header_as_data)

    // Clean up
    release s.accumulated
    free s
    return IFF_OK
```

The decoded result is then routed by the parser:
- If inside a PROP scope: stored in the property dictionary
- If inside a FORM with a FormDecoder: passed to `process_chunk`
- Otherwise: released

---

## Section 9 --- FormDecoder

### 9.1 The FormDecoder Vtable

A `FormDecoder` assembles a high-level entity from the chunks and nested forms
within a FORM container. It has four required callbacks and two optional
container lifecycle callbacks:

```c
struct IFF_FormDecoder {
    // Called when entering the FORM
    IFF_TYPE_RESULT (*begin_decode)(
        struct IFF_Parser_State *state
        , void **custom_state
    );

    // Called for each decoded chunk within the FORM
    IFF_TYPE_RESULT (*process_chunk)(
        struct IFF_Parser_State *state
        , void *custom_state
        , struct IFF_Tag *chunk_tag
        , struct IFF_ContextualData *contextual_data
    );

    // Called for each decoded nested FORM (direct or bubbled through CAT/LIST)
    IFF_TYPE_RESULT (*process_nested_form)(
        struct IFF_Parser_State *state
        , void *custom_state
        , struct IFF_Tag *form_type
        , void *final_entity
    );

    // Called when leaving the FORM; produces the final entity
    IFF_TYPE_RESULT (*end_decode)(
        struct IFF_Parser_State *state
        , void *custom_state
        , void **out_final_entity
    );

    // OPTIONAL: Called when a child CAT or LIST container is entered.
    // Allows tracking container grouping boundaries.
    IFF_TYPE_RESULT (*enter_container)(
        struct IFF_Parser_State *state
        , void *custom_state
        , struct IFF_Tag *container_variant   // CAT or LIST
        , struct IFF_Tag *container_type
    );

    // OPTIONAL: Called when a child CAT or LIST container is exited.
    IFF_TYPE_RESULT (*leave_container)(
        struct IFF_Parser_State *state
        , void *custom_state
        , struct IFF_Tag *container_variant
        , struct IFF_Tag *container_type
    );
};
```

### 9.2 Container Entity Routing

Entities produced by FORMs nested inside CAT or LIST containers are
automatically routed to the nearest ancestor FORM that has a `FormDecoder`
with a `process_nested_form` callback. This routing is transparent --- the
decoder does not need to know whether a nested FORM was a direct child or
arrived through an intermediate container.

To distinguish grouping, decoders can implement the optional
`enter_container` / `leave_container` callbacks. The parser calls these when
entering and leaving any CAT or LIST that sits between the decoder's FORM
and the nested FORMs. This produces a SAX-like event stream:

```
begin_decode
  process_chunk(BMHD, ...)
  enter_container(CAT, BBBB)        // group 1 opens
    process_nested_form(BBBB, e1)
    process_nested_form(BBBB, e2)
  leave_container(CAT, BBBB)        // group 1 closes
  enter_container(CAT, CCCC)        // group 2 opens
    process_nested_form(CCCC, e3)
  leave_container(CAT, CCCC)        // group 2 closes
end_decode
```

Nesting is tracked correctly at any depth:

```
  enter_container(LIST, XXXX)       // depth 1
    enter_container(CAT, BBBB)      // depth 2
      process_nested_form(BBBB, e1)
    leave_container(CAT, BBBB)
  leave_container(LIST, XXXX)
```

Root-level containers (no parent FORM) route entities to
`session->final_entity` as before. No container events are dispatched.

### 9.3 Registration

Form decoders are registered by form type tag:

```
IFF_Parser_Factory_RegisterFormDecoder(factory, &ILBM_tag, ilbm_decoder);
```

### 9.4 PROP Resolution from Within a Decoder

Both `process_chunk` and `end_decode` receive a `Parser_State` that exposes
`FindProp`. This allows decoders to pull shared properties:

```
IFF_TYPE_RESULT ilbm_end(IFF_Parser_State *state, void *cs, void **out_entity):
    ILBM_State *s = cs

    // Check if a CMAP was provided as a PROP
    if s.palette == NULL:
        IFF_ContextualData *prop_cmap = NULL
        IFF_Parser_State_FindProp(state, &CMAP_tag, &prop_cmap)
        if prop_cmap != NULL:
            s.palette = extract_palette(prop_cmap.data)

    // Assemble the final image entity
    *out_entity = build_image(s.header, s.palette, s.body)
    cleanup(s)
    return IFF_OK
```

### 9.5 Example: Decoding an ILBM Image

```
struct ILBM_State {
    BitmapHeader *header;
    Palette      *palette;
    PixelData    *body;
};

IFF_TYPE_RESULT ilbm_begin(state, custom_state):
    allocate ILBM_State -> s
    s.header = s.palette = s.body = NULL
    *custom_state = s
    return IFF_OK

IFF_TYPE_RESULT ilbm_process_chunk(state, cs, chunk_tag, contextual_data):
    ILBM_State *s = cs
    if chunk_tag matches BMHD:
        s.header = decode_header(contextual_data.data)
    else if chunk_tag matches CMAP:
        s.palette = decode_palette(contextual_data.data)
    else if chunk_tag matches BODY:
        s.body = decode_pixels(contextual_data.data, s.header)
    // Unknown chunks are silently ignored (forward compatibility)
    return IFF_OK

IFF_TYPE_RESULT ilbm_process_nested_form(state, cs, form_type, entity):
    // ILBM typically does not nest forms
    // But if it did, handle here
    return IFF_OK

IFF_TYPE_RESULT ilbm_end(state, cs, out_entity):
    ILBM_State *s = cs
    *out_entity = build_image(s.header, s.palette, s.body)
    free(s)
    return IFF_OK
```

---

# Part IV: Writing Encoders

## Section 10 --- ChunkEncoder

A `ChunkEncoder` has a single callback that serializes a structured object into
raw bytes:

```c
struct IFF_ChunkEncoder {
    IFF_TYPE_RESULT (*encode)(
        struct IFF_Generator_State *state
        , void *source_object
        , struct VPS_Data **out_data
    );
};
```

This is simpler than the decoder side because there is no sharding on encode ---
the encoder produces the complete chunk data in one call.

## Section 11 --- FormEncoder

### 11.1 The FormEncoder Vtable

A `FormEncoder` mirrors `FormDecoder` with four required callbacks and two
optional container group callbacks:

```c
struct IFF_FormEncoder {
    // Set up encoding state from the source entity
    IFF_TYPE_RESULT (*begin_encode)(
        struct IFF_Generator_State *state
        , void *source_entity
        , void **custom_state
    );

    // Produce chunks one at a time; set done=1 when finished
    IFF_TYPE_RESULT (*produce_chunk)(
        struct IFF_Generator_State *state
        , void *custom_state
        , struct IFF_Tag *out_tag
        , struct VPS_Data **out_data
        , char *out_done
    );

    // Produce nested FORMs one at a time; set done=1 when finished
    IFF_TYPE_RESULT (*produce_nested_form)(
        struct IFF_Generator_State *state
        , void *custom_state
        , struct IFF_Tag *out_form_type
        , void **out_nested_entity
        , char *out_done
    );

    // Clean up encoding state
    IFF_TYPE_RESULT (*end_encode)(
        struct IFF_Generator_State *state
        , void *custom_state
    );

    // OPTIONAL: Produce container groups (CAT/LIST) wrapping nested FORMs.
    // Called in a loop after produce_chunk, before produce_nested_form.
    IFF_TYPE_RESULT (*begin_container_group)(
        struct IFF_Generator_State *state
        , void *custom_state
        , struct IFF_Tag *out_container_variant  // CAT or LIST
        , struct IFF_Tag *out_container_type
        , char *out_done
    );

    // OPTIONAL: Produce the next FORM inside a container group.
    // Called in a loop after begin_container_group opens a container.
    IFF_TYPE_RESULT (*produce_grouped_form)(
        struct IFF_Generator_State *state
        , void *custom_state
        , struct IFF_Tag *out_form_type
        , void **out_nested_entity
        , char *out_done
    );
};
```

### 11.2 Factory-Driven EncodeForm

The generator's `EncodeForm` function drives the encoding lifecycle:

```
1. begin_encode(entity) → custom_state
2. Loop: produce_chunk()           → WriteChunk for each
3. Loop: begin_container_group()   → BeginCat/BeginList
     Loop: produce_grouped_form()  → EncodeForm for each
     EndCat/EndList
4. Loop: produce_nested_form()     → EncodeForm for each (direct, no wrapper)
5. end_encode()
```

Steps 3-4 allow encoders to produce both grouped (CAT/LIST-wrapped) and
direct nested FORMs. Encoders that don't need container groups leave
`begin_container_group` and `produce_grouped_form` as NULL (steps 3 skipped).

### 11.3 Example: Encoding an ILBM Image

```
struct ILBM_EncState {
    Image *image;
    int    chunk_index;
    char   chunks_done;
};

IFF_TYPE_RESULT ilbm_begin_encode(state, entity, custom_state):
    allocate ILBM_EncState -> s
    s.image = (Image*)entity
    s.chunk_index = 0
    s.chunks_done = 0
    *custom_state = s
    return IFF_OK

IFF_TYPE_RESULT ilbm_produce_chunk(state, cs, out_tag, out_data, out_done):
    ILBM_EncState *s = cs
    switch s.chunk_index:
        case 0:
            *out_tag = BMHD_tag
            *out_data = encode_header(s.image.header)
            s.chunk_index++
        case 1:
            *out_tag = CMAP_tag
            *out_data = encode_palette(s.image.palette)
            s.chunk_index++
        case 2:
            *out_tag = BODY_tag
            *out_data = encode_pixels(s.image.body)
            s.chunks_done = 1
    *out_done = s.chunks_done
    return IFF_OK

IFF_TYPE_RESULT ilbm_produce_nested_form(state, cs, out_type, out_entity, out_done):
    *out_done = 1   // ILBM has no nested forms
    return IFF_OK

IFF_TYPE_RESULT ilbm_end_encode(state, cs):
    free(cs)
    return IFF_OK
```

Registration and invocation:

```
// Register
IFF_Generator_Factory_RegisterFormEncoder(factory, &ILBM_tag, ilbm_encoder);

// Use
IFF_Generator_WriteHeader(gen, &header);
IFF_Generator_EncodeForm(gen, &ILBM_tag, my_image);
IFF_Generator_Flush(gen);
```

---

# Part V: Parser Configuration

## Section 12 --- Strict References

By default, the parser silently consumes `' REF'` directives when no segment
resolver is registered, regardless of whether the reference is mandatory or
optional. This ensures forward compatibility with files containing references
that the host application does not support.

When `strict_references` is set to `1`, the parser will fail on mandatory
`' REF'` directives (those with `id_size > 0`) if no resolver is registered.
This enforces the spec's requirement that mandatory references must be
resolvable.

```c
// After creating the parser:
parser->strict_references = 1;
```

---

## Section 13 --- Migrating from the `char` Convention

Earlier VulpesIFF returned `char`, with `1` for success, and so did
VulpesCore. Both moved together, so code written against either old API
inverts the same way and there is no longer a mixed boundary between them.
Predicates are the one place the boolean form survives on purpose. Both types
are integers, so nothing in the compiler will flag a missed one --- the code
builds clean and misbehaves at runtime.

Two habits make that tractable.

**Build with the signature guard.** Callbacks are the one class of mistake that
is otherwise invisible, because an explicit cast silences the compiler and the
polarity only inverts at runtime:

```
-Werror=incompatible-pointer-types -Werror=int-conversion
```

This catches a decoder or encoder still declared `char (*)(...)`, and it catches
a status accidentally returned from a function that yields a pointer. It cannot
see a callback that reaches you through a `void **` out-parameter --- those
still need reading.

**Audit returns, not call sites.** Searching for `!IFF_` finds the shape you
thought of. The returns that bite are the ones whose value is computed rather
than written as a literal, because a search for `return 0;` and `return 1;`
never sees them:

```c
return *item != 0;              /* allocation succeeded  -> now reads as failure */
return di == dest_size;         /* decompression is complete                     */
return all_match;               /* every checksum matched                        */
return state == Complete;       /* the parse finished                            */
```

Each of those reports success as `1`. Walking every function that returns
`IFF_TYPE_RESULT` and checking that each return is `IFF_OK`, `IFF_FAIL`, a
propagated result, or a call to another converted function finds them all.

### 13.1 Shapes worth checking by hand

| Shape                                              | Why it is easy to miss                        |
|----------------------------------------------------|-----------------------------------------------|
| `if (!result \|\| other)`                            | Compound conditions do not match `if (!result)` |
| `if (!A(x) && Find(y))`                            | Mixed in one condition: predicates keep the boolean form, so only the status terms flip |
| `x = Call(...)` then `if (x)` much later           | No `!` anywhere for a search to catch         |
| A helper with two return paths                     | One may forward a status, the other a predicate |
| `char x = Call(...)`                               | Truncates a line number to its low 8 bits     |
| `while (Call(...))`                                | Stops on success and spins on failure         |
| `x->hook(...)` through a struct member             | The signature guard already accepted the pointer, so it cannot see this |

### 13.2 Success branches

The inversion is not always "add a `!`". A test written as a *success* branch
loses one:

```c
/* before: proceed when resolution succeeded */
if (parser->segment_resolver(ctx, id, &fh))

/* after */
if (!parser->segment_resolver(ctx, id, &fh))
```

Read each site for what it means, rather than applying a uniform edit.

---

## License

This guide is part of the VulpesIFF project and is released under the
MIT License.
