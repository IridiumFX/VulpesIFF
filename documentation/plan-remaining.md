Implementation Plan: Remaining Spec Gaps
=========================================

Last updated: 2026-02-22

All IFF-2025 spec gaps are now complete, including DEF/REF
(segmentation/inclusion).


1. Sharding ('    ' Directive) -- DONE
---------------------------------------

Implemented across `IFF_Scope` and `IFF_Parser`:
- Added `last_chunk_decoder`, `last_chunk_state`, `last_chunk_tag` to IFF_Scope.
- `FlushLastDecoder` helper finalizes pending decoders and routes results.
- `Parse_Chunk` defers `end_decode` when SHARDING is enabled.
- `Parse_Directive` dispatches `'    '` to pending decoder's `process_shard()`.
- Flush calls at all scope exit points (FORM, PROP).


2. Strict Container Validation -- DONE
---------------------------------------

Implemented using Option (B): validation inside `Parse_Container_FORM`,
after reading the type tag, checks if the parent scope is a CAT or LIST
with `STRICT_CONTAINERS` set and a non-wildcard type. Rejects on mismatch.


3. IFF-85 Mode Locking -- DONE
-------------------------------

Implemented: `iff85_locked` field added to `IFF_Parser_Session`. Set to 1
in `Parse_Segment` when the first tag is a container. `Parse_Directive`
guard at top rejects all directives except `'    '` (filler) when locked.


4. Scope Guards -- DONE
------------------------

Implemented in `ExecuteDirective`, `IFF_ACTION_UPDATE_FLAGS` case. Three
validation checks before applying new flags:
1. Size widening: reject if child size field > parent size field.
2. Blobbed-to-progressive: reject progressive inside blobbed parent.
3. Tag widening: reject if child tag width > parent tag width.
Parent accessed via `scope_stack->head->next->data`.


Priority Order
--------------

1. ~~**CHK/SUM wiring**~~ -- DONE.
2. ~~**Sharding**~~ -- DONE.
3. ~~**Strict containers**~~ -- DONE.
4. ~~**IFF-85 locking**~~ -- DONE.
5. ~~**Scope guards**~~ -- DONE.
6. ~~**DEF/REF (segmentation/inclusion)**~~ -- DONE.
