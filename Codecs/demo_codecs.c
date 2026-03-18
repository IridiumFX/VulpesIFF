#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include "ILBM/ILBM_Types.h"
#include "ILBM/ILBM_Loader.h"
#include "SVX8/SVX8_Types.h"
#include "SVX8/SVX8_Codec.h"
#include "SVX8/SVX8_Loader.h"

/* ── ILBM info ─────────────────────────────────────────────────────── */

static void print_ilbm_info(const char *path)
{
	printf("=== ILBM: %s ===\n\n", path);

	struct ILBM_Result *img = VPS_ILBM_LoadFromFile(path);
	if (!img)
	{
		printf("  Failed to load.\n\n");
		return;
	}

	printf("  Dimensions : %u x %u pixels\n", img->width, img->height);
	printf("  Baseline   : %u\n", img->baseline);
	printf("  Pixel data : %u bytes (RGBA8888)\n",
		(unsigned)(img->width * img->height * 4));

	/* Scan for unique colors and basic statistics. */
	VPS_TYPE_32U total = (VPS_TYPE_32U)img->width * img->height;
	VPS_TYPE_32U transparent = 0;
	VPS_TYPE_64U r_sum = 0, g_sum = 0, b_sum = 0;

	for (VPS_TYPE_32U i = 0; i < total; i++)
	{
		VPS_TYPE_8U r = img->pixels[i * 4 + 0];
		VPS_TYPE_8U g = img->pixels[i * 4 + 1];
		VPS_TYPE_8U b = img->pixels[i * 4 + 2];
		VPS_TYPE_8U a = img->pixels[i * 4 + 3];

		r_sum += r;
		g_sum += g;
		b_sum += b;

		if (a == 0) transparent++;
	}

	printf("  Avg color  : R=%u G=%u B=%u\n",
		(unsigned)(r_sum / total),
		(unsigned)(g_sum / total),
		(unsigned)(b_sum / total));

	if (transparent > 0)
	{
		printf("  Transparent: %u pixels (%.1f%%)\n",
			transparent, 100.0 * transparent / total);
	}

	/* ASCII art thumbnail (fit to ~40 columns). */
	int thumb_w = img->width > 80 ? 80 : img->width;
	int thumb_h = (int)((double)img->height / img->width * thumb_w * 0.5);
	if (thumb_h < 1) thumb_h = 1;
	if (thumb_h > 60) thumb_h = 60;

	const char *ramp = " .:-=+*#%@";
	int ramp_len = 10;

	printf("\n  Preview (%dx%d):\n\n", thumb_w, thumb_h);

	for (int y = 0; y < thumb_h; y++)
	{
		printf("    ");
		for (int x = 0; x < thumb_w; x++)
		{
			int sx = x * img->width / thumb_w;
			int sy = y * img->height / thumb_h;
			VPS_TYPE_32U idx = ((VPS_TYPE_32U)sy * img->width + sx) * 4;

			VPS_TYPE_8U r = img->pixels[idx + 0];
			VPS_TYPE_8U g = img->pixels[idx + 1];
			VPS_TYPE_8U b = img->pixels[idx + 2];

			int luma = (r * 299 + g * 587 + b * 114) / 1000;
			int ci = luma * (ramp_len - 1) / 255;
			printf("%c", ramp[ci]);
		}
		printf("\n");
	}

	printf("\n");
	free(img->pixels);
	free(img);
}

/* ── 8SVX info ─────────────────────────────────────────────────────── */

static void print_svx8_info(const char *path)
{
	printf("=== 8SVX: %s ===\n\n", path);

	struct SVX8_Result *snd = VPS_SVX8_LoadFromFile(path);
	if (!snd)
	{
		printf("  Failed to load.\n\n");
		return;
	}

	struct SVX8_VoiceHeader *v = &snd->vhdr;
	VPS_TYPE_32U total_samples = v->oneShotHiSamples + v->repeatHiSamples;

	printf("  Sample rate  : %u Hz\n", v->samplesPerSec);
	printf("  One-shot     : %u samples\n", v->oneShotHiSamples);
	printf("  Repeat       : %u samples\n", v->repeatHiSamples);
	printf("  Total        : %u samples\n", total_samples);

	if (v->samplesPerSec > 0 && total_samples > 0)
	{
		double duration = (double)total_samples / v->samplesPerSec;
		printf("  Duration     : %.3f seconds\n", duration);
	}

	printf("  Octaves      : %u\n", v->ctOctave);
	printf("  Compression  : %s\n",
		v->sCompression == 0 ? "none" :
		v->sCompression == 1 ? "Fibonacci delta" : "unknown");
	printf("  Volume       : 0x%08X (%.2f)\n",
		v->volume, (double)v->volume / 65536.0);

	if (snd->samples)
	{
		printf("  Sample data  : %u bytes\n", (unsigned)snd->samples->limit);

		/* Waveform statistics. */
		VPS_TYPE_SIZE n = snd->samples->limit;
		VPS_TYPE_8S *pcm = (VPS_TYPE_8S *)snd->samples->bytes;
		VPS_TYPE_8S min_val = 0, max_val = 0;
		VPS_TYPE_64S sum = 0;
		VPS_TYPE_64U energy = 0;

		for (VPS_TYPE_SIZE i = 0; i < n; i++)
		{
			VPS_TYPE_8S s = pcm[i];
			if (s < min_val) min_val = s;
			if (s > max_val) max_val = s;
			sum += s;
			energy += (VPS_TYPE_64U)(s * s);
		}

		double rms = 0;
		if (n > 0) rms = sqrt((double)energy / n);

		printf("  Amplitude    : min=%d max=%d\n", min_val, max_val);
		printf("  DC offset    : %.2f\n", n > 0 ? (double)sum / n : 0.0);
		printf("  RMS level    : %.2f\n", rms);

		/* ASCII waveform (40 columns, ~16 rows). */
		int wave_w = 60;
		int wave_h = 12;

		printf("\n  Waveform:\n\n");
		printf("    +127 |");
		for (int x = 0; x < wave_w; x++) printf("-");
		printf("|\n");

		for (int y = 0; y < wave_h; y++)
		{
			int level = 127 - (y * 255 / (wave_h - 1));
			if (level >= -5 && level <= 5)
				printf("       0 |");
			else
				printf("         |");

			for (int x = 0; x < wave_w; x++)
			{
				VPS_TYPE_SIZE si = (VPS_TYPE_SIZE)x * n / wave_w;
				/* Average a window of samples for this column. */
				VPS_TYPE_SIZE window = n / wave_w;
				if (window < 1) window = 1;
				VPS_TYPE_8S lo = 0, hi = 0;
				for (VPS_TYPE_SIZE w = 0; w < window && si + w < n; w++)
				{
					VPS_TYPE_8S s = pcm[si + w];
					if (s < lo) lo = s;
					if (s > hi) hi = s;
				}

				int lo_row = (127 - lo) * (wave_h - 1) / 255;
				int hi_row = (127 - hi) * (wave_h - 1) / 255;
				if (y >= hi_row && y <= lo_row)
					printf("#");
				else if (level >= -5 && level <= 5)
					printf("-");
				else
					printf(" ");
			}
			printf("|\n");
		}

		printf("    -128 |");
		for (int x = 0; x < wave_w; x++) printf("-");
		printf("|\n");
	}

	printf("\n");
	if (snd->samples) VPS_Data_Release(snd->samples);
	free(snd);
}

/* ── main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	printf("\nVulpesIFF Codec Demo\n");
	printf("====================\n\n");

	if (argc < 2)
	{
		printf("Usage: %s <file.ilbm|file.8svx> [file2 ...]\n\n", argv[0]);
		printf("Supported formats:\n");
		printf("  .ilbm  IFF Interleaved Bitmap (ILBM)\n");
		printf("  .8svx  IFF 8-bit Sampled Voice (8SVX)\n\n");
		printf("Running built-in demo with bundled resources...\n\n");

		print_ilbm_info("Codecs/Resources/GJ_Gorilla.ilbm");
		print_svx8_info("Codecs/Resources/OhNo.8svx");
		return 0;
	}

	for (int i = 1; i < argc; i++)
	{
		const char *path = argv[i];
		const char *ext = strrchr(path, '.');

		if (ext && (strcmp(ext, ".ilbm") == 0 || strcmp(ext, ".iff") == 0
			|| strcmp(ext, ".lbm") == 0))
		{
			print_ilbm_info(path);
		}
		else if (ext && (strcmp(ext, ".8svx") == 0 || strcmp(ext, ".svx") == 0))
		{
			print_svx8_info(path);
		}
		else
		{
			/* Try both, see which succeeds. */
			struct ILBM_Result *img = VPS_ILBM_LoadFromFile(path);
			if (img)
			{
				free(img->pixels);
				free(img);
				print_ilbm_info(path);
			}
			else
			{
				print_svx8_info(path);
			}
		}
	}

	return 0;
}
