/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#ifndef EFI_VARAUTH_H
#define EFI_VARAUTH_H

#include <efi/efi.h>

#define EFI_CERT_TYPE_PKCS7_GUID                                               \
	{ 0x4aafd29d,                                                          \
	  0x68df,                                                              \
	  0x49ee,                                                              \
	  { 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7 } }

#define EFI_CERT_X509_GUID                                                     \
	{ 0xa5c059a1,                                                          \
	  0x94e4,                                                              \
	  0x4aa7,                                                              \
	  { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } }

#define EFI_CERT_SHA256_GUID                                                   \
	{ 0xc1c41626,                                                          \
	  0x504c,                                                              \
	  0x4092,                                                              \
	  { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } }

#define EFI_IMAGE_SECURITY_DATABASE_GUID                                       \
	{ 0xd719b2cb,                                                          \
	  0x3d3a,                                                              \
	  0x4596,                                                              \
	  { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } }

#ifndef EFI_VARIABLE_NON_VOLATILE
#define EFI_VARIABLE_NON_VOLATILE 0x00000001
#endif

#ifndef EFI_VARIABLE_BOOTSERVICE_ACCESS
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#endif

#ifndef EFI_VARIABLE_RUNTIME_ACCESS
#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004
#endif

#ifndef EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#endif

#ifndef EFI_VARIABLE_APPEND_WRITE
#define EFI_VARIABLE_APPEND_WRITE 0x00000040
#endif

typedef struct {
	UINT32 dwLength;
	UINT16 wRevision;
	UINT16 wCertificateType;
	UINT8 bCertificate[];
} WIN_CERTIFICATE;

#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma GCC diagnostic ignored "-Wpedantic"
typedef struct {
	WIN_CERTIFICATE Hdr;
	EFI_GUID CertType;
	UINT8 CertData[];
} WIN_CERTIFICATE_UEFI_GUID;
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wflexible-array-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
typedef struct {
	EFI_TIME TimeStamp;
	WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;
#pragma GCC diagnostic pop

typedef struct {
	EFI_GUID SignatureOwner;
	UINT8 SignatureData[];
} EFI_SIGNATURE_DATA;

typedef struct {
	EFI_GUID SignatureType;
	UINT32 SignatureListSize;
	UINT32 SignatureHeaderSize;
	UINT32 SignatureSize;
} EFI_SIGNATURE_LIST;

#endif /* EFI_VARAUTH_H */
