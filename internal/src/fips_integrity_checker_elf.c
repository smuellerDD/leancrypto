/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "build_bug_on.h"
#include "fips_integrity_check.h"
#include "helper.h"

/*
 * The GNU linker creates these variables as start and endpoint of ELF sections
 */
extern const void _start_init;
extern const void _end_init;
extern const void _start_text;
extern const void _end_text;
extern const void _start_rodata;
extern const void _end_rodata;

/*
 * Integrity check compare values - they cannot be part of the regular rodata
 * section as they would then modify the image part. Therefore, we need to place
 * them into a separate section which is not part of the rodata that the
 * variables above wrap.
 */
#ifdef LC_FIPS_VALUES_GENERATED
#include "fips_integrity_checker_values.h"
#else
__attribute__ ((section("fips_integrity_data")))
static const struct lc_fips_integrity_sections secs[] = { {
	.desc = "Text Segment",
	.section_start_p = &_start_text,
	.section_end_p = &_end_text,
	.expected_digest = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	},
}, {
	.desc = "Init Segment",
	.section_start_p = &_start_init,
	.section_end_p = &_end_init,
	.expected_digest = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	},
}, {
	.desc = "ROData Segment",
	.section_start_p = &_start_rodata,
	.section_end_p = &_end_rodata,
	.expected_digest = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	},
} };
#endif

/* Generator for the header file above */
static void
fips_integrity_checker_build(struct lc_fips_integrity_section_actual *act)
{
	unsigned int i;

	BUILD_BUG_ON(ARRAY_SIZE(secs) != 3);

	printf("Init segment: start (0x%lx), end (0x%lx), length (0x%lx)\n",
	       (unsigned long)&_start_init, (unsigned long)&_end_init,
	       (unsigned long)((uint8_t *)&_end_init - (uint8_t *)&_start_init));
	printf("Text segment: start (0x%lx), end (0x%lx), length (0x%lx)\n",
	       (unsigned long)&_start_text, (unsigned long)&_end_text,
	       (unsigned long)((uint8_t *)&_end_text - (uint8_t *)&_start_text));
	printf("ROData segment: start (0x%lx), end (0x%lx), length (0x%lx)\n",
	       (unsigned long)&_start_rodata, (unsigned long)&_end_rodata,
	       (unsigned long)((uint8_t *)&_end_rodata - (uint8_t *)&_start_rodata));

	fprintf(stderr, "__attribute__ ((section(\"fips_integrity_data\")))\n");
	fprintf(stderr,
		"static const struct lc_fips_integrity_sections secs[] = { {\n");

	/* Text segment */
	fprintf(stderr, "\t.desc = \"%s\",\n", secs[0].desc);
	fprintf(stderr, "\t.section_start_p = &_start_text,\n");
	fprintf(stderr, "\t.section_end_p = &_end_text,\n");
	fprintf(stderr, "\t.expected_digest = {\n\t\t");

	for (i = 0; i < LC_SHA3_256_SIZE_DIGEST; i++) {
		fprintf(stderr, "0x%.2x, ", *(act->digest + i));
		if (!((i + 1) % 8)) {
			if (i == LC_SHA3_256_SIZE_DIGEST - 1)
				fprintf(stderr, "\n");
			else
				fprintf(stderr, "\n\t\t");
		}
	}

	act++;

	fprintf(stderr, "\t},\n");
	fprintf(stderr, "}, {\n");

	/* Init segment */
	fprintf(stderr, "\t.desc = \"%s\",\n", secs[1].desc);
	fprintf(stderr, "\t.section_start_p = &_start_init,\n");
	fprintf(stderr, "\t.section_end_p = &_end_init,\n");
	fprintf(stderr, "\t.expected_digest = {\n\t\t");

	for (i = 0; i < LC_SHA3_256_SIZE_DIGEST; i++) {
		fprintf(stderr, "0x%.2x, ", *(act->digest + i));
		if (!((i + 1) % 8)) {
			if (i == LC_SHA3_256_SIZE_DIGEST - 1)
				fprintf(stderr, "\n");
			else
				fprintf(stderr, "\n\t\t");
		}
	}

	act++;

	fprintf(stderr, "\t},\n");
	fprintf(stderr, "}, {\n");

	/* ROData segment */
	fprintf(stderr, "\t.desc = \"%s\",\n", secs[2].desc);
	fprintf(stderr, "\t.section_start_p = &_start_rodata,\n");
	fprintf(stderr, "\t.section_end_p = &_end_rodata,\n");
	fprintf(stderr, "\t.expected_digest = {\n\t\t");

	for (i = 0; i < LC_SHA3_256_SIZE_DIGEST; i++) {
		fprintf(stderr, "0x%.2x, ", *(act->digest + i));
		if (!((i + 1) % 8)) {
			if (i == LC_SHA3_256_SIZE_DIGEST - 1)
				fprintf(stderr, "\n");
			else
				fprintf(stderr, "\n\t\t");
		}
	}

	fprintf(stderr, "\t},\n");
	fprintf(stderr, "} };\n");
}

/*
 * This constructor is part of the regular "text" section and thus subject to
 * the integrity test.
 */
__attribute__ ((constructor))
static void fips_integrity_checker(void)
{
	struct lc_fips_integrity_section_actual act[ARRAY_SIZE(secs)];

	fips140_mode_enable();
	if (fips_integrity_check(secs, act, ARRAY_SIZE(secs))) {
		fips_integrity_checker_build(act);
		exit(1);
	}
}
