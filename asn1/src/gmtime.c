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

#include "ext_headers_internal.h"
#include "lc_x509_common.h"
#include "visibility.h"

#define LC_SEC (1)
#define LC_MIN (60 * LC_SEC)
#define LC_HOUR (60 * LC_MIN)
#define LC_DAY (24 * LC_HOUR)
#define LC_YEAR (365 * LC_DAY)
#define LC_IS_LEAP(year)                                                       \
	(year % 4) ? 0 : (year % 100) ? 1 : (year % 400) ? 0 : 1

LC_INTERFACE_FUNCTION(int, lc_gmtime, time64_t timeval, struct lc_tm *tm)
{
	unsigned int days_month, feb_days, days;

	if (!tm || timeval < 0)
		return -EINVAL;

	/*
	 * First step: get the years from the time value. This incorporates
	 * the assessment for leap years. Each detected year implies that
	 * the code subtracts the time for that year.
	 */
	tm->year = 1970;
	while (timeval >= LC_YEAR) {
		timeval -= LC_YEAR;

		/*
		 * Adjust the days if we just had the leap year - then one day
		 * goes to the old year as it had 366 days.
		 */
		if (LC_IS_LEAP(tm->year)) {
			if (timeval < LC_DAY) {
				/*
				  * this is the 366th day - as we are in the
				  * current year, add it to the time value and
				  * stop loop.
				  */
				timeval += LC_YEAR;
				break;
			} else {
				/* 366th day belongs to old year */
				timeval -= LC_DAY;
				tm->year++;
			}
		} else {
			/* Regular year */
			tm->year++;
		}
	}

	/*
	 * Obtain the days and months since Epoch
	 */
	days = (unsigned int)(timeval / (LC_DAY));
	timeval -= days * (LC_DAY);
	days += 1;

	/* Account for February 29 */
	if (LC_IS_LEAP(tm->year))
		feb_days = 29;
	else
		feb_days = 28;
	days_month = (31 + /* January */
		      feb_days + /* February */
		      31 + /* March */
		      30 + /* April */
		      31 + /* May */
		      30 + /* June */
		      31 + /* July */
		      31 + /* August */
		      30 + /* September */
		      31 + /* October */
		      30); /* November */

	do {
		/* Check December */
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 12;
			break;
		}

		/* Check November */
		days_month -= 30;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 11;
			break;
		}

		/* Check October */
		days_month -= 31;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 10;
			break;
		}

		/* Check September */
		days_month -= 30;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 9;
			break;
		}

		/* Check August */
		days_month -= 31;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 8;
			break;
		}

		/* Check July */
		days_month -= 31;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 7;
			break;
		}

		/* Check June */
		days_month -= 30;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 6;
			break;
		}

		/* Check May */
		days_month -= 31;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 5;
			break;
		}

		/* Check April */
		days_month -= 30;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 4;
			break;
		}

		/* Check March */
		days_month -= 31;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 3;
			break;
		}

		/* Check February */
		days_month -= feb_days;
		if (days > days_month) {
			tm->day = (unsigned char)(days - days_month);
			tm->month = 2;
			break;
		}

		/* January */
		tm->day = (unsigned char)(days);
		tm->month = 1;

	} while (0);

	/* Hour */
	tm->hour = (unsigned char)(timeval / LC_HOUR);
	timeval -= tm->hour * LC_HOUR;

	/* Minutes */
	tm->min = (unsigned char)(timeval / LC_MIN);
	timeval -= tm->min * LC_MIN;

	/* Second */
	tm->sec = (unsigned char)(timeval / LC_SEC);

	return 0;
}
