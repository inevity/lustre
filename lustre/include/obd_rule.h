/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2022, DDN/Whamcloud Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Rule parsing and matching functions.
 *
 * lustre/include/obd_rule.h
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#ifndef __OBD_RULE_H__
#define __OBD_RULE_H__

#include <linux/fs.h>
#include <libcfs/libcfs.h>

struct cfs_rule {
	char			*rl_conds_str;
	struct list_head	 rl_conds;
};

struct cfs_matcher {
	__u32		 mc_uid;
	__u32		 mc_gid;
	__u32		 mc_projid;
	__u64		 mc_size;
	struct qstr	*mc_name;
};

int cfs_rule_parse_init(struct cfs_rule *rule, const char *id);
int cfs_rule_match(struct cfs_rule *rule, struct cfs_matcher *matcher);
void cfs_rule_fini(struct cfs_rule *rule);
#endif /* __OBD_RULE_H__ */
