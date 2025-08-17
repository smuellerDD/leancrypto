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

#include "lc_x509_common.h"
#include "visibility.h"

#define LC_DAY (24 * 60 * 60)
#define LC_YEAR (365 * LC_DAY)

/**
 * Trivial conversion of time to human-readable time value
 *
 * It only shows UTC considering that Epoch is UTC (i.e. it does not apply
 * any time-zone conversions).
 *
 * Furthermore, it does not apply leap seconds.
 *
 * @param [in] timeval Time in seconds since Epoch
 * @param [out] tm Decoded time
 *
 * @return 9 on success; < 0 on error
 */
LC_INTERFACE_FUNCTION(int, lc_gmtime, time64_t timeval, struct lc_tm *tm)
{
	unsigned int days_month, feb_days, days;

	if (!tm || timeval < 0)
		return -EINVAL;

	tm->year = 1970;
	while (timeval >= LC_YEAR) {
		unsigned int leap = 0;

		timeval -= LC_YEAR;
		tm->year++;

		if (tm->year >= 1972) {
			leap = tm->year - 1972;

			if (leap % 4 == 1) {
				if (leap % 100 == 1) {
					if (leap % 400 == 1)
						leap = 1;
					else
						leap = 0;
				} else {
					leap = 1;
				}
			} else {
				leap = 0;
			}
		}

		/*
		 * Adjust the days if we just had the leap year - then one day
		 * goes to the old year as it had 366 days.
		 */
		if (leap) {
			if (timeval < LC_DAY) {
				tm->year--;
				timeval += LC_YEAR;
			} else {
				timeval -= LC_DAY;
			}
		}
	}

	/*
	 * Obtain the days and months since Epoch
	 */
	days = (unsigned int)(timeval / (LC_DAY));
	timeval -= days * (LC_DAY);
	days += 1;

	/* Account for February 29 */
	feb_days = (tm->year != 2000 && tm->year % 4 != 0) ? 28 : 29;
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
	tm->hour = (unsigned char)(timeval / (60 * 60));
	timeval -= tm->hour * (60 * 60);

	/* Minutes */
	tm->min = (unsigned char)(timeval / (60));
	timeval -= tm->min * (60);

	/* Second */
	tm->sec = (unsigned char)(timeval);

	return 0;
}
