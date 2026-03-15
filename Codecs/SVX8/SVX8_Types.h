#pragma once
#include <vulpes/VPS_Types.h>

struct VPS_Data;

/**
 * @brief 8SVX Voice Header (VHDR chunk).
 * All fields stored big-endian in the IFF file.
 */
struct SVX8_VoiceHeader
{
	VPS_TYPE_32U oneShotHiSamples;   /* # samples in one-shot part. */
	VPS_TYPE_32U repeatHiSamples;    /* # samples in repeat part. */
	VPS_TYPE_32U samplesPerHiCycle;  /* # samples per cycle in highest octave. */
	VPS_TYPE_16U samplesPerSec;      /* Data sampling rate. */
	VPS_TYPE_8U  ctOctave;           /* # octaves of waveforms. */
	VPS_TYPE_8U  sCompression;       /* 0=none, 1=Fibonacci delta. */
	VPS_TYPE_32S volume;             /* Fixed-point volume (0x10000 = unity). */
};

/**
 * @brief Intermediate state assembled by the 8SVX FormDecoder.
 */
struct SVX8_State
{
	struct SVX8_VoiceHeader vhdr;
	char has_vhdr;
	char has_body;
	struct VPS_Data* body_data;  /* Signed 8-bit PCM samples. Owned. */
};
