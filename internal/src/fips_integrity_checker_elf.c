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

#include "alignment.h"
#include "build_bug_on.h"
#include "ext_headers.h"
#include "fips_integrity_check.h"
#include "helper.h"
#include "lc_status.h"
#include "visibility.h"

/*
 * The GNU linker creates these variables as start and endpoint of ELF sections
 */
extern const void _start_init;
extern const void _end_init;
extern const void _start_ctors;
extern const void _end_ctors;
extern const void _start_text;
extern const void _end_text;
extern const void LC_FIPS_RODATA_SECTION_NAME_START;
extern const void LC_FIPS_RODATA_SECTION_NAME_STOP;

/*
 * Integrity check compare values - they cannot be part of the regular rodata
 * section as they would then modify the image part. Therefore, we need to place
 * them into a separate section which is not part of the rodata that the
 * variables above wrap.
 */
static const struct lc_fips_integrity_sections secs[] = {
	{
		.section_start_p = &_start_text,
		.section_end_p = &_end_text,
	},
	{
		.section_start_p = &_start_init,
		.section_end_p = &_end_init,
	},
	{
		.section_start_p = &_start_ctors,
		.section_end_p = &_end_ctors,
	},
	{
		.section_start_p = &LC_FIPS_RODATA_SECTION_NAME_START,
		.section_end_p = &LC_FIPS_RODATA_SECTION_NAME_STOP,

/*
	 * The ROData segment is currently excluded from being checked, because
	 * ROData in the function fips_integrity_checker_build in this
	 * file seems to read unallocated memory on ARMv8.
	 *
	 * But the check of ROData is considered not required for FIPS 140
	 * compliance because the ROData contains the static data for
	 * self-tests, but the power-up self test are considered to verify the
	 * appropriateness of the ROData.
	 */
#if 0
}, {
	.section_start_p = &_start_rodata,
	.section_end_p = &_end_rodata,
#endif
	}
};

#ifdef LC_FIPS_VALUES_GENERATED
#include "fips_integrity_checker_values.h"
#else
__attribute__((section(
	"fips_integrity_data"))) static const uint8_t expected_digest[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
#endif

/* Generator for the header file above */
static void
fips_integrity_checker_build(const uint8_t act[LC_SHA3_256_SIZE_DIGEST])
{
	unsigned int i;

	fprintf(stderr,
		"//Init section: start (0x%lx), end (0x%lx), length (0x%lx)\n",
		(unsigned long)&_start_init, (unsigned long)&_end_init,
		(unsigned long)((uint8_t *)&_end_init -
				(uint8_t *)&_start_init));
	fprintf(stderr,
		"//Ctors section: start (0x%lx), end (0x%lx), length (0x%lx)\n",
		(unsigned long)&_start_ctors, (unsigned long)&_end_ctors,
		(unsigned long)((uint8_t *)&_end_ctors -
				(uint8_t *)&_start_ctors));
	fprintf(stderr,
		"//Text section: start (0x%lx), end (0x%lx), length (0x%lx)\n",
		(unsigned long)&_start_text, (unsigned long)&_end_text,
		(unsigned long)((uint8_t *)&_end_text -
				(uint8_t *)&_start_text));
	// fprintf(stderr, "//ROData section: start (0x%lx), end (0x%lx), length (0x%lx)\n",
	//        (unsigned long)&_start_rodata, (unsigned long)&_end_rodata,
	//        (unsigned long)((uint8_t *)&_end_rodata -
	// 		       (uint8_t *)&_start_rodata));

	fprintf(stderr,
		"//ROData1 section: start (0x%lx), end (0x%lx), length (0x%lx)\n",
		(unsigned long)&LC_FIPS_RODATA_SECTION_NAME_START,
		(unsigned long)&LC_FIPS_RODATA_SECTION_NAME_STOP,
		(unsigned long)((uint8_t *)&LC_FIPS_RODATA_SECTION_NAME_STOP -
				(uint8_t *)&LC_FIPS_RODATA_SECTION_NAME_START));

	for (i = 0; i < LC_SHA3_256_SIZE_DIGEST; i++)
		fprintf(stderr, "0x%.2x, ", *(act + i));
}

LC_INTERFACE_FUNCTION(void, lc_fips_integrity_checker, void)
{
	uint8_t act[LC_SHA3_256_SIZE_DIGEST] __align(8) = { 0 };

	if (fips_integrity_check(secs, ARRAY_SIZE(secs), expected_digest,
				 act)) {
		fips_integrity_checker_build(act);
		lc_memset_secure(act, 0, sizeof(act));
		exit(1);
	}

	lc_memset_secure(act, 0, sizeof(act));
}

/*
 * This constructor is part of the regular "text" section and thus subject to
 * the integrity test.
 */
__attribute__((constructor)) static void fips_integrity_checker_dep(void)
{
	fips140_mode_enable();
	lc_fips_integrity_checker();
}
