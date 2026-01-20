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
/*
 * This implementation is intended to provide a drop-in replacement for the
 * sbsign tool from
 * http://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git.
 *
 * The file is derived from this code with the following license:
 */
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
#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>

#include <getopt.h>

#include "efivars.h"

#include "helper.h"
#include "lc_status.h"
#include "lc_x509_parser.h"
#include "lc_x509_generator_file_helper.h"
#include "list.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

static struct statfs statfstype;

#define EFIVARS_MOUNTPOINT	"/sys/firmware/efi/efivars"
#define PSTORE_FSTYPE		((typeof(statfstype.f_type))0x6165676C)
#define EFIVARS_FSTYPE		((typeof(statfstype.f_type))0xde5e81e4)

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
	{ 0xd719b2cb, 0x3d3a, 0x4596, \
	{ 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } }

static const char *toolname = "sbkeysync";

static const uint32_t sigdb_attrs = EFI_VARIABLE_NON_VOLATILE |
	EFI_VARIABLE_BOOTSERVICE_ACCESS |
	EFI_VARIABLE_RUNTIME_ACCESS |
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
	EFI_VARIABLE_APPEND_WRITE;

struct key_database_type {
	const char	*name;
	EFI_GUID	guid;
};

struct key_database_type keydb_types[] = {
	{ "PK",  EFI_GLOBAL_VARIABLE },
	{ "KEK", EFI_GLOBAL_VARIABLE },
	{ "db",  EFI_IMAGE_SECURITY_DATABASE_GUID },
	{ "dbx", EFI_IMAGE_SECURITY_DATABASE_GUID },
};

enum keydb_type {
	KEYDB_PK = 0,
	KEYDB_KEK = 1,
	KEYDB_DB = 2,
	KEYDB_DBX = 3,
};

static const char *default_keystore_dirs[] = {
	"/etc/secureboot/keys",
	"/usr/share/secureboot/keys",
};

struct key {
	EFI_GUID			type;
	size_t				id_len;
	uint8_t				*id;

	char				*description;

	struct list_entry		list;

	/* set for keys loaded from a filesystem keystore */
	struct fs_keystore_entry	*keystore_entry;
};

typedef int (*key_parse_func)(struct key *, uint8_t *, size_t);

struct cert_type {
	EFI_GUID	guid;
	key_parse_func	parse;
};

struct key_database {
	const struct key_database_type	*type;
	struct list_entry		keys;
};

struct keyset {
	struct key_database	pk;
	struct key_database	kek;
	struct key_database	db;
	struct key_database	dbx;
};

struct fs_keystore_entry {
	const struct key_database_type	*type;
	const char			*root;
	char			*name;
	uint8_t				*data;
	size_t				len;
	struct list_entry		keystore_list;
	struct list_entry		new_list;
};

struct fs_keystore {
	struct list_entry	keys;
};

struct sync_context {
	const char		*efivars_dir;
	struct keyset		*filesystem_keys;
	struct keyset		*firmware_keys;
	struct fs_keystore	*fs_keystore;
	char		**keystore_dirs;
	unsigned int		n_keystore_dirs;
	struct list_entry	new_keys;
	bool			verbose;
	bool			dry_run;
	bool			set_pk;
};


#define GUID_STRLEN (8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12 + 1)
static void guid_to_str(const EFI_GUID *guid, char *str)
{
	snprintf(str, GUID_STRLEN,
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			guid->Data1, guid->Data2, guid->Data3,
			guid->Data4[0], guid->Data4[1],
			guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5],
			guid->Data4[6], guid->Data4[7]);
}

static int sha256_key_parse(struct key *key, uint8_t *data, size_t len)
{
	static const unsigned int sha256_id_size = 256 / 8;
	size_t i;
	int ret = 0;

	if (len != sha256_id_size)
		return -EINVAL;

	key->id = calloc(1, sha256_id_size);
	CKNULL(key->id, -ENOMEM);
	memcpy(key, data, sha256_id_size);
	key->id_len = sha256_id_size;

	key->description = calloc(1, len * 2 + 1);
	CKNULL(key->description, -ENOMEM);
	for (i = 0; i < len; i++)
		snprintf(&key->description[i*2], 3, "%02x", data[i]);
	key->description[len*2] = '\0';

out:
	return ret;
}

static void
print_x509_name_component(char *buf, size_t bufmaxlen, unsigned int *comma,
			  const char *prefix, const char *string,
			  size_t string_len)
{
	size_t buflen;

	if (!string_len)
		return;

	buflen = strlen(buf);

	snprintf(buf + buflen, bufmaxlen, "%s%s%s",
		 *comma ? ", " : "", prefix, string);

	*comma = 1;
}

static int print_x509_name(char *buf, size_t bufmaxlen,
			   const struct lc_x509_certificate *x509)
{
	const char *string;
	size_t string_len;
	unsigned int i;
	int ret;

	i = 0;

	CKINT(lc_x509_cert_get_subject_c(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "C = ", string,
				  string_len);

	CKINT(lc_x509_cert_get_subject_st(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "ST = ", string,
				  string_len);

	CKINT(lc_x509_cert_get_subject_o(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "O = ", string,
				  string_len);

	CKINT(lc_x509_cert_get_subject_ou(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "OU = ", string,
				  string_len);

	CKINT(lc_x509_cert_get_subject_cn(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "CN = ", string,
				  string_len);

	CKINT(lc_x509_cert_get_subject_email(x509, &string, &string_len));
	print_x509_name_component(buf, bufmaxlen, &i, "Email = ", string,
				  string_len);

out:
	return ret;
}

static int x509_key_parse(struct key *key, uint8_t *data, size_t len)
{
	struct workspace {
		struct lc_x509_certificate x509;
	};
	const int description_len = 160;
	const uint8_t *serial;
	size_t seriallen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT_LOG(lc_x509_cert_decode(&ws->x509, data, len),
		  "Parsing of input failed\n");

	CKINT_LOG(lc_x509_cert_get_serial(&ws->x509, &serial, &seriallen),
		  "Failed to obtain serial number from X.509 certificate\n");

	key->id = calloc(1, seriallen);
	CKNULL(key->id, -ENOMEM);
	memcpy(key, serial, seriallen);
	key->id_len = seriallen;

	key->description = calloc(1, description_len);
	CKNULL(key->description, -ENOMEM);

	CKINT(print_x509_name(key->description, description_len, &ws->x509));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

struct cert_type cert_types[] = {
	{ EFI_CERT_SHA256_GUID, sha256_key_parse },
	{ EFI_CERT_X509_GUID, x509_key_parse },
};

static int guidcmp(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(EFI_GUID));
}

static int key_parse(struct key *key, const EFI_GUID *type, uint8_t *data,
		     size_t len)
{
	char guid_str[GUID_STRLEN];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++) {
		if (guidcmp(&cert_types[i].guid, type))
			continue;

		return cert_types[i].parse(key, data, len);
	}

	guid_to_str(type, guid_str);
	printf("warning: unknown signature type found:\n  %s\n", guid_str);
	return -EINVAL;

}

typedef int (*sigdata_fn)(EFI_SIGNATURE_DATA *, size_t, const EFI_GUID *, void *);

/**
 * Iterates an buffer of EFI_SIGNATURE_LISTs (at db_data, of length len),
 * and calls fn on each EFI_SIGNATURE_DATA item found.
 *
 * fn is passed the EFI_SIGNATURE_DATA pointer, and the length of the
 * signature data (including GUID header), the type of the signature list,
 * and a context pointer.
 */
static int sigdb_iterate(uint8_t *db_data, size_t len, sigdata_fn fn, void *arg)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	unsigned int i, j;
	int ret = 0;

	if (len == 0)
		return 0;

	if (len < sizeof(*siglist))
		return -1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0, siglist = (EFI_SIGNATURE_LIST *)(db_data + i);
	     i + sizeof(*siglist) <= len &&
	     i + siglist->SignatureListSize > i &&
	     i + siglist->SignatureListSize <= len;
	     i += siglist->SignatureListSize,
	     siglist = (EFI_SIGNATURE_LIST *)(db_data + i)) {

		/* ensure that the header & sig sizes are sensible */
		if (siglist->SignatureHeaderSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize < sizeof(*sigdata))
			continue;

		/* iterate through the (constant-sized) signature data blocks */
		for (j = sizeof(*siglist) + siglist->SignatureHeaderSize;
		     j < siglist->SignatureListSize;
		     j += siglist->SignatureSize)
		{
			sigdata = (EFI_SIGNATURE_DATA *)((uint8_t *)(siglist) + j);

			CKINT(fn(sigdata, siglist->SignatureSize,
				 &siglist->SignatureType, arg));

		}

	}
#pragma GCC diagnostic pop

out:
	return ret;
}

struct keydb_add_ctx {
	struct fs_keystore_entry *ke;
	struct key_database *kdb;
	struct keyset *keyset;
};

static int keydb_add_key(EFI_SIGNATURE_DATA *sigdata, size_t len,
			 const EFI_GUID *type, void *arg)
{
	struct keydb_add_ctx *add_ctx = arg;
	struct key *key;
	int ret = 0;

	key = calloc(1, sizeof(struct key));
	CKNULL(key, -ENOMEM);

	ret = key_parse(key, type, sigdata->SignatureData,
			len - sizeof(*sigdata));
	if (ret) {
		free(key);
		return 0;
	}
	key->keystore_entry = add_ctx->ke;
	key->type = *type;

	list_add(&add_ctx->kdb->keys, &key->list);

out:
	return ret;
}

static int read_firmware_keydb(struct sync_context *ctx,
			       struct key_database *kdb)
{
	struct keydb_add_ctx add_ctx;
	char guid_str[GUID_STRLEN];
	char filename[FILENAME_MAX];
	uint8_t *buf = NULL;
	int ret;
	size_t len;

	add_ctx.keyset = ctx->firmware_keys;
	add_ctx.kdb = kdb;
	add_ctx.ke = NULL;

	guid_to_str(&kdb->type->guid, guid_str);

	snprintf(filename, sizeof(filename), "%s/%s-%s",
		 ctx->efivars_dir, kdb->type->name, guid_str);

	CKINT(get_data(filename, &buf, &len, lc_pem_flag_nopem));

	/* efivars files start with a 32-bit attribute block */
	if (len < sizeof(uint32_t))
		goto out;

	buf += sizeof(uint32_t);
	len -= sizeof(uint32_t);

	CKINT(sigdb_iterate(buf, len, keydb_add_key, &add_ctx));

out:
	release_data(buf, len, lc_pem_flag_nopem);
	return ret;
}

static void __attribute__((format(printf, 2, 3))) print_keystore_key_error(
		struct fs_keystore_entry *ke, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "Invalid key %s/%s\n - \n", ke->root, ke->name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static int read_filesystem_keydb(struct sync_context *ctx,
				 struct key_database *kdb)
{
	EFI_GUID cert_type_pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
	EFI_VARIABLE_AUTHENTICATION_2 *auth;
	struct keydb_add_ctx add_ctx;
	struct fs_keystore_entry *ke;
	int rc;

	add_ctx.keyset = ctx->filesystem_keys;
	add_ctx.kdb = kdb;

	list_for_each(ke, &ctx->fs_keystore->keys, keystore_list) {
		size_t len;
		uint8_t *buf;

		if (ke->len == 0)
			continue;

		if (ke->type != kdb->type)
			continue;

		/* parse the three data structures:
		 *  EFI_VARIABLE_AUTHENTICATION_2 token
		 *  EFI_SIGNATURE_LIST
		 *  EFI_SIGNATURE_DATA
		 * ensuring that we have enough data for each
		 */

		buf = ke->data;
		len = ke->len;

		if (len < sizeof(*auth)) {
			print_keystore_key_error(ke, "does not contain an "
				"EFI_VARIABLE_AUTHENTICATION_2 descriptor");
			continue;
		}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		auth = (EFI_VARIABLE_AUTHENTICATION_2 *)buf;
#pragma GCC diagnostic pop

		if (guidcmp(&auth->AuthInfo.CertType, &cert_type_pkcs7)) {
			print_keystore_key_error(ke, "unknown cert type");
			continue;
		}

		if (auth->AuthInfo.Hdr.dwLength > len) {
			print_keystore_key_error(ke,
					"invalid WIN_CERTIFICATE length");
			continue;
		}

		/* the dwLength field includes the size of the WIN_CERTIFICATE,
		 * but not the other data in the EFI_VARIABLE_AUTHENTICATION_2
		 * descriptor */
		buf += sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;
		len -= sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;

		add_ctx.ke = ke;
		rc = sigdb_iterate(buf, len, keydb_add_key, &add_ctx);
		if (rc) {
			print_keystore_key_error(ke, "error parsing "
					"EFI_SIGNATURE_LIST");
			continue;
		}

	}

	return 0;
}

static int read_keysets(struct sync_context *ctx)
{
	read_firmware_keydb(ctx, &ctx->firmware_keys->pk);
	read_firmware_keydb(ctx, &ctx->firmware_keys->kek);
	read_firmware_keydb(ctx, &ctx->firmware_keys->db);
	read_firmware_keydb(ctx, &ctx->firmware_keys->dbx);

	read_filesystem_keydb(ctx, &ctx->filesystem_keys->pk);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->kek);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->db);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->dbx);

	return 0;
}

static int check_pk(struct sync_context *ctx)
{
	struct key *key;
	int i = 0;

	list_for_each(key, &ctx->filesystem_keys->pk.keys, list)
		i++;

	return (i <= 1) ? 0 : 1;
}

static void print_keyset(struct keyset *keyset, const char *name)
{
	struct key_database *kdbs[] =
		{ &keyset->pk, &keyset->kek, &keyset->db, &keyset->dbx };
	struct key *key;
	unsigned int i;

	printf("%s keys:\n", name);

	for (i = 0; i < ARRAY_SIZE(kdbs); i++) {
		printf("  %s:\n", kdbs[i]->type->name);

		list_for_each(key, &kdbs[i]->keys, list) {
			printf("    %s\n", key->description);
			if (key->keystore_entry)
				printf("     from %s/%s\n",
						key->keystore_entry->root,
						key->keystore_entry->name);
		}
	}
}

static int check_efivars_mount(const char *mountpoint)
{
	struct statfs statbuf;

	if (statfs(mountpoint, &statbuf) == -1)
		return -errno;

	if (statbuf.f_type != EFIVARS_FSTYPE && statbuf.f_type != PSTORE_FSTYPE)
		return -EFAULT;

	return 0;
}

static int keystore_entry_read(struct fs_keystore_entry *ke)
{
	char path[FILENAME_MAX];
	int ret;

	snprintf(path, sizeof(path), "%s/%s", ke->root, ke->name);
	CKINT(get_data_memory(path, &ke->data, &ke->len, lc_pem_flag_nopem));

out:
	return ret;
}

static bool keystore_contains_file(struct fs_keystore *keystore,
				   const char *filename)
{
	struct fs_keystore_entry *ke;

	list_for_each(ke, &keystore->keys, keystore_list) {
		if (!strcmp(ke->name, filename))
			return true;
	}

	return false;
}

static int update_keystore(struct fs_keystore *keystore, const char *root)
{
	struct fs_keystore_entry *ke;
	unsigned int i;
	char name[FILENAME_MAX];
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(keydb_types); i++) {
		struct dirent *dirent;
		DIR *dir;

		snprintf(name, sizeof(name), "%s/%s", root,
			 keydb_types[i].name);

		dir = opendir(name);
		if (!dir)
			continue;

		for (dirent = readdir(dir); dirent; dirent = readdir(dir)) {
			char *name_tmp;
			size_t len;

			if (dirent->d_name[0] == '.')
				continue;

			snprintf(name, sizeof(name), "%s/%s",
				 keydb_types[i].name, dirent->d_name);

			if (keystore_contains_file(keystore, name))
				continue;

			ke = calloc(1, sizeof(struct fs_keystore_entry));
			CKNULL(ke, -ENOMEM);
			len = strlen(name) + 1;
			name_tmp = calloc(1, len);
			CKNULL(name_tmp, -ENOMEM);
			snprintf(name_tmp, len, "%s", name);
			ke->name = name_tmp;
			ke->root = root;
			ke->type = &keydb_types[i];

			if (keystore_entry_read(ke)) {
				free(name_tmp);
				free(ke);
			} else {
				list_add(&keystore->keys, &ke->keystore_list);
			}
		}

		closedir(dir);
	}

out:
	return ret;
}

static int read_keystore(struct sync_context *ctx)
{
	struct fs_keystore *keystore;
	unsigned int i;
	int ret = 0;

	keystore = calloc(1, sizeof(struct fs_keystore));
	CKNULL(keystore, -ENOMEM);
	LIST_ENTRY_INIT(keystore->keys);

	for (i = 0; i < ctx->n_keystore_dirs; i++) {
		CKINT(update_keystore(keystore, ctx->keystore_dirs[i]));
	}

	ctx->fs_keystore = keystore;

out:
	return ret;
}

static void print_keystore(struct fs_keystore *keystore)
{
	struct fs_keystore_entry *ke;

	printf("Filesystem keystore:\n");

	list_for_each(ke, &keystore->keys, keystore_list)
		printf("  %s/%s [%zd bytes]\n", ke->root, ke->name, ke->len);
}

static int key_cmp(struct key *a, struct key *b)
{
	if (a->id_len != b->id_len)
		return (int)(a->id_len - b->id_len);

	return memcmp(a->id, b->id, a->id_len);
}

/**
 * Finds the set-difference of the filesystem and firmware keys, and
 * populates ctx->new_keys with the keystore_entries that should be
 * inserted into firmware
 */
static int find_new_keys(struct sync_context *ctx)
{
	struct {
		struct key_database *fs_kdb, *fw_kdb;
	} kdbs[] = {
		{ &ctx->filesystem_keys->pk,  &ctx->firmware_keys->pk },
		{ &ctx->filesystem_keys->kek, &ctx->firmware_keys->kek },
		{ &ctx->filesystem_keys->db,  &ctx->firmware_keys->db },
		{ &ctx->filesystem_keys->dbx, &ctx->firmware_keys->dbx },
	};
	unsigned int i;
	int n = 0;

	for (i = 0; i < ARRAY_SIZE(kdbs); i++ ) {
		struct fs_keystore_entry *ke;
		struct key *fs_key, *fw_key;
		bool found;

		list_for_each(fs_key, &kdbs[i].fs_kdb->keys, list) {
			found = false;
			list_for_each(fw_key, &kdbs[i].fw_kdb->keys, list) {
				if (!key_cmp(fs_key, fw_key)) {
					found = true;
					break;
				}
			}
			if (found)
				continue;

			/* add the keystore entry if it's not already present */
			found = false;
			list_for_each(ke, &ctx->new_keys, new_list) {
				if (fs_key->keystore_entry == ke) {
					found = true;
					break;
				}
			}

			if (found)
				continue;

			list_add(&ctx->new_keys,
					&fs_key->keystore_entry->new_list);
			n++;
		}
	}

	return n;
}

static void print_new_keys(struct sync_context *ctx)
{
	struct fs_keystore_entry *ke;

	printf("New keys in filesystem:\n");

	list_for_each(ke, &ctx->new_keys, new_list)
		printf(" %s/%s\n", ke->root, ke->name);
}

static int insert_key(struct sync_context *ctx, struct fs_keystore_entry *ke)
{
	char guid_str[GUID_STRLEN];
	char efivars_filename[FILENAME_MAX];
	size_t buf_len;
	uint8_t *buf;
	int fd, ret = 0;
	ssize_t written;

	fd = -1;

	if (ctx->verbose)
		printf("Inserting key update %s/%s into %s\n",
				ke->root, ke->name, ke->type->name);

	/* we create a contiguous buffer of attributes & key data, so that
	 * we write to the efivars file in a single syscall */
	buf_len = sizeof(sigdb_attrs) + ke->len;
	buf = calloc(1, buf_len);
	CKNULL(buf, -ENOMEM);
	memcpy(buf, &sigdb_attrs, sizeof(sigdb_attrs));
	memcpy(buf + sizeof(sigdb_attrs), ke->data, ke->len);

	guid_to_str(&ke->type->guid, guid_str);

	snprintf(efivars_filename, sizeof(efivars_filename), "%s/%s-%s",
		 ctx->efivars_dir, ke->type->name, guid_str);

	fd = open(efivars_filename, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		fprintf(stderr,	"Can't create key file %s: %s\n",
				efivars_filename, strerror(errno));
		goto out;
	}

	written = write(fd, buf, buf_len);
	if (written <= 0) {
		ret = -errno;
		fprintf(stderr, "Error writing key update: %s\n",
			strerror(errno));
		goto out;
	}

	if ((size_t)written != buf_len) {
		fprintf(stderr, "Partial write during key update: "
				"wrote %zd bytes, expecting %zu\n",
				written, buf_len);
		ret = -EFAULT;
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	if (buf)
		free(buf);
	if (ret)
		fprintf(stderr, "Error syncing keystore file %s/%s\n",
				ke->root, ke->name);
	return ret;
}

static int insert_new_keys(struct sync_context *ctx)
{
	struct fs_keystore_entry *ke, *ke_pk;
	int pks, ret;

	pks = 0;
	ke_pk = NULL;

	list_for_each(ke, &ctx->new_keys, new_list) {

		/* we handle PK last */
		if (ke->type == &keydb_types[KEYDB_PK]) {
			ke_pk = ke;
			pks++;
			continue;
		}

		CKINT(insert_key(ctx, ke));
	}

	if (pks == 0 || !ctx->set_pk)
		return 0;

	if (pks > 1) {
		fprintf(stderr, "Skipping PK update due to mutiple PKs\n");
		return -EFAULT;
	}

	CKINT(insert_key(ctx, ke_pk));

out:
	return ret;
}

static struct keyset *init_keyset(void)
{
	struct keyset *keyset;

	keyset = calloc(1, sizeof(struct keyset));
	if (!keyset)
		return NULL;

	LIST_ENTRY_INIT(keyset->pk.keys);
	keyset->pk.type = &keydb_types[KEYDB_PK];

	LIST_ENTRY_INIT(keyset->kek.keys);
	keyset->kek.type = &keydb_types[KEYDB_KEK];

	LIST_ENTRY_INIT(keyset->db.keys);
	keyset->db.type = &keydb_types[KEYDB_DB];

	LIST_ENTRY_INIT(keyset->dbx.keys);
	keyset->dbx.type = &keydb_types[KEYDB_DBX];

	return keyset;
}

static struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "efivars-path", required_argument, NULL, 'e' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "dry-run", no_argument, NULL, 'n' },
	{ "pk", no_argument, NULL, 'p' },
	{ "no-default-keystores", no_argument, NULL, 'd' },
	{ "keystore", required_argument, NULL, 'k' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options]\n"
		"Update EFI key databases from the filesystem\n"
		"\n"
		"Options:\n"
		"\t--efivars-path <dir>  Path to efivars mountpoint\n"
		"\t                       (or regular directory for testing)\n"
		"\t--verbose             Print verbose progress information\n"
		"\t--dry-run             Don't update firmware key databases\n"
		"\t--pk                  Set PK\n"
		"\t--keystore <dir>      Read keys from <dir>/{db,dbx,KEK}/*\n"
		"\t                       (can be specified multiple times,\n"
		"\t                       first dir takes precedence)\n"
		"\t--no-default-keystores\n"
		"\t                      Don't read keys from the default\n"
		"\t                       keystore dirs\n",
		toolname);
}

static void version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto %s\n", toolname);
	fprintf(stderr, "%s\n", version);
}

static void add_keystore_dir(struct sync_context *ctx, const char *dir)
{
	if (!ctx->keystore_dirs) {
		ctx->keystore_dirs = calloc(1, sizeof(uintptr_t));
		ctx->n_keystore_dirs++;
	} else {
		ctx->keystore_dirs = realloc(
			ctx->keystore_dirs,
			++ctx->n_keystore_dirs * sizeof(uintptr_t));
	}

	ctx->keystore_dirs[ctx->n_keystore_dirs - 1] = strdup(dir);
}


static void release_key(struct key *key)
{
	if (!key)
		return;

	if (key->id)
		free(key->id);
	if (key->description)
		free(key->description);
	free(key);
}

static void release_ctx(struct sync_context *ctx)
{
	struct {
		struct key_database *fs_kdb;
	} kdbs[] = {
		{ &ctx->filesystem_keys->pk },
		{ &ctx->filesystem_keys->kek },
		{ &ctx->filesystem_keys->db },
		{ &ctx->filesystem_keys->dbx },
	};
	struct fs_keystore_entry *ke, *tmp;
	unsigned int i;

	if (!ctx)
		return;

	if (ctx->fs_keystore) {
		list_for_each_guarded(ke, tmp, &ctx->fs_keystore->keys, keystore_list) {
			lc_free(ke->data);
			free(ke->name);
			free(ke);
		}
		free(ctx->fs_keystore);
	}

	if (ctx->n_keystore_dirs) {
		for (i = 0; i < ctx->n_keystore_dirs; i++)
			free(ctx->keystore_dirs[i]);
		free(ctx->keystore_dirs);
	}

	if (ctx->filesystem_keys) {
		for (i = 0; i < ARRAY_SIZE(kdbs); i++ ) {
			struct key *key;

			list_for_each(key, &kdbs[i].fs_kdb->keys, list) {
				release_key(key);
			}
		}

		free(ctx->filesystem_keys);
	}
	if (ctx->firmware_keys)
		free(ctx->firmware_keys);

	free(ctx);
}

int main(int argc, char **argv)
{
	bool use_default_keystore_dirs;
	struct sync_context *ctx;
	int ret = 0;

	use_default_keystore_dirs = true;
	ctx = calloc(1, sizeof(struct sync_context));
	LIST_ENTRY_INIT(ctx->new_keys);

	for (;;) {
		int idx, c;
		c = getopt_long(argc, argv, "e:dpkvhV", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'e':
			ctx->efivars_dir = optarg;
			break;
		case 'd':
			use_default_keystore_dirs = false;
			break;
		case 'k':
			add_keystore_dir(ctx, optarg);
			break;
		case 'p':
			ctx->set_pk = true;
			break;
		case 'v':
			ctx->verbose = true;
			break;
		case 'n':
			ctx->dry_run = true;
			break;
		case 'V':
			version();
			goto out;
		case 'h':
			usage();
			goto out;
		}
	}

	if (argc != optind) {
		usage();
		return EXIT_FAILURE;
	}

	ctx->filesystem_keys = init_keyset();
	CKNULL(ctx->filesystem_keys, -ENOMEM);
	ctx->firmware_keys = init_keyset();
	CKNULL(ctx->firmware_keys, -ENOMEM);

	if (!ctx->efivars_dir) {
		ctx->efivars_dir = EFIVARS_MOUNTPOINT;
		CKINT_LOG(check_efivars_mount(ctx->efivars_dir),
			  "Can't access efivars filesystem "
			  "at %s, aborting\n", ctx->efivars_dir);
	}

	if (use_default_keystore_dirs) {
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(default_keystore_dirs); i++)
			add_keystore_dir(ctx, default_keystore_dirs[i]);
	}

	read_keystore(ctx);

	if (ctx->verbose)
		print_keystore(ctx->fs_keystore);

	read_keysets(ctx);
	if (ctx->verbose) {
		print_keyset(ctx->firmware_keys, "firmware");
		print_keyset(ctx->filesystem_keys, "filesystem");
	}

	if (check_pk(ctx))
		fprintf(stderr, "WARNING: multiple PKs found in filesystem\n");

	find_new_keys(ctx);

	if (ctx->verbose)
		print_new_keys(ctx);

	if (!ctx->dry_run) {
		CKINT(insert_new_keys(ctx));
	}

out:
	release_ctx(ctx);
	return ret;
}
