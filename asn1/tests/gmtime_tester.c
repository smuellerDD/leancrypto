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

#include "ext_headers.h"
#include "lc_x509_common.h"
#include "ret_checkers.h"
#include "visibility.h"

static int gmtime_tester(time64_t timeval)
{
	struct tm *time_detail;
	struct lc_tm lc_tm;
	int ret = 0;

	CKINT(lc_gmtime(timeval, &lc_tm));

	time_detail = gmtime((time64_t *)&timeval);
	CKNULL(time_detail, -EFAULT);

	if (lc_tm.year != time_detail->tm_year + 1900) {
		printf("lc_gmtime year %u, gmtime year %u, epoch %" PRIu64 "\n",
		       lc_tm.year, time_detail->tm_year + 1900, timeval);
		ret += 1;
	}

	if (lc_tm.month != time_detail->tm_mon + 1) {
		printf("lc_gmtime month %u, gmtime month %u, epoch %" PRIu64
		       "\n",
		       lc_tm.month, time_detail->tm_mon + 1, timeval);
		ret += 1;
	}

	if (lc_tm.day != time_detail->tm_mday) {
		printf("lc_gmtime day %u, gmtime day %u, epoch %" PRIu64 "\n",
		       lc_tm.day, time_detail->tm_mday, timeval);
		ret += 1;
	}

	if (lc_tm.hour != time_detail->tm_hour) {
		printf("lc_gmtime hour %u, gmtime hour %u, epoch %" PRIu64 "\n",
		       lc_tm.hour, time_detail->tm_hour, timeval);
		ret += 1;
	}

	if (lc_tm.min != time_detail->tm_min) {
		printf("lc_gmtime min %u, gmtime min %u, epoch %" PRIu64 "\n",
		       lc_tm.min, time_detail->tm_min, timeval);
		ret += 1;
	}

	if (lc_tm.sec != time_detail->tm_sec) {
		printf("lc_gmtime sec %u, gmtime sec %u, epoch %" PRIu64 "\n",
		       lc_tm.sec, time_detail->tm_sec, timeval);
		ret += 1;
	}

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	time64_t timeval;
	int ret;

	(void)argc;
	(void)argv;

	timeval = time(NULL);

	while (timeval) {
		ret = gmtime_tester(timeval);
		if (ret)
			return ret;

		/*
		 * Subtract prime number of days as hour/min/sec are usually no
		 * issue.
		 */
#define SUBTRACT (60 * 60 * 24 * 111)
		timeval = timeval > SUBTRACT ? timeval - SUBTRACT : 0;
	}

	return 0;
}
