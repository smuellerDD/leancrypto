/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_UUID_H
#define LC_UUID_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Convert a binary buffer into a UUID
 *
 * @param [in] uuid Binary buffer of 16 bytes
 * @param [out] uuid_str UUID
 */
void lc_uuid_bin2hex(const uint8_t uuid[16], char uuid_str[37]);

/**
 * @brief Convert a UUID into a binary representation
 *
 * @param [in] uuid_str UUID
 * @param [in] uuid_strlen Length of UUID buffer (must be at least 36 bytes)
 * @param [out] uuid Binary buffer with converted UUID
 *
 * @return 0 on success; < 0 on error
 */
int lc_uuid_hex2bin(const char *uuid_str, size_t uuid_strlen, uint8_t uuid[16]);

/**
 * @brief Generate random UUID following RFC 4122 section 4.4
 *
 * @param [out] uuid_str [out] NULL-terminated UUID string
 *
 * @return 0 on success; < 0 on error
 */
int lc_uuid_random(char uuid_str[37]);

/**
 * @brief Generate time-based UUID following RFC 4122 section 4.2
 *
 * @param [out] uuid_str [out] NULL-terminated UUID string
 * @param [in] node node identifier the UUID applies to
 *
 * @return 0 on success; < 0 on error
 */
int lc_uuid_time(char uuid_str[37], uint64_t node);

#ifdef __cplusplus
}
#endif

#endif /* LC_UUID_H */
