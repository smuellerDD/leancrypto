// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "lc_status.h"
#include "leancrypto_kernel.h"
#include "ret_checkers.h"

#define LC_PROC_STATUS_FILENAME "leancrypto"

static int lc_proc_status_show(struct seq_file *m, void *v)
{
#define LC_PROC_STATUS_BUF_SIZE 2000
	char *buf;
	int ret;

	buf = kzalloc(LC_PROC_STATUS_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return PTR_ERR(buf);

	CKINT(lc_status(buf, LC_PROC_STATUS_BUF_SIZE));
	seq_write(m, buf, strlen(buf));

out:
	kfree(buf);
	return ret;
}

int __init lc_proc_status_show_init(void)
{
	proc_create_single(LC_PROC_STATUS_FILENAME, 0444, NULL, &lc_proc_status_show);
	return 0;
}

void lc_proc_status_show_exit(void)
{
	remove_proc_subtree(LC_PROC_STATUS_FILENAME, NULL);
}
