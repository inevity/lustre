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
 * lustre/obdclass/obd_rule.c
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#include <obd_rule.h>
#include <obd_support.h>

/* User/Group/Project ID */
struct rule_match_id {
	__u32			rmi_id;
	struct list_head	rmi_linkage;
};

/* Lazy file size */
struct rule_match_size {
	__u64			rms_size;
	struct list_head	rms_linkage;
};

/* wildcard file name */
struct rule_match_fname {
	char			*rmf_name;
	struct list_head	 rmf_linkage;
};

enum rule_field {
	RULE_FIELD_UID,
	RULE_FIELD_GID,
	RULE_FIELD_PROJID,
	RULE_FIELD_FNAME,
	RULE_FIELD_SIZE,
	RULE_FIELD_MAX
};

enum rule_field_op {
	RULE_FIELD_OP_EQ	= 0,
	RULE_FIELD_OP_LT	= 1,
	RULE_FIELD_OP_GT	= 2,
	RULE_FIELD_OP_MAX	= 3,
	RULE_FIELD_OP_INV	= RULE_FIELD_MAX,
};

struct rule_expression {
	struct list_head	re_linkage;
	enum rule_field		re_field;
	enum rule_field_op	re_opc;
	union {
		struct list_head	re_cond;
		__u64			re_size;
		__u32			re_id;
	};
};

struct rule_conjunction {
	/* link to disjunction */
	struct list_head	rc_linkage;
	/* list of logical conjunction */
	struct list_head	rc_expressions;
};

/* Rule freeing */
static void rule_id_list_free(struct rule_expression *expr)
{
	struct rule_match_id *id, *n;

	if (expr->re_opc == RULE_FIELD_OP_EQ) {
		list_for_each_entry_safe(id, n, &expr->re_cond, rmi_linkage) {
			list_del_init(&id->rmi_linkage);
			OBD_FREE_PTR(id);
		}
	}
}

static void rule_fname_list_free(struct rule_expression *expr)
{
	struct rule_match_fname *fname, *n;

	LASSERT(expr->re_opc == RULE_FIELD_OP_EQ);
	list_for_each_entry_safe(fname, n, &expr->re_cond, rmf_linkage) {
		OBD_FREE(fname->rmf_name, strlen(fname->rmf_name) + 1);
		list_del_init(&fname->rmf_linkage);
		OBD_FREE_PTR(fname);
	}
}

static void rule_size_list_free(struct rule_expression *expr)
{
	struct rule_match_size *sz, *n;

	if (expr->re_opc == RULE_FIELD_OP_EQ) {
		list_for_each_entry_safe(sz, n, &expr->re_cond, rms_linkage) {
			list_del_init(&sz->rms_linkage);
			OBD_FREE_PTR(sz);
		}
	}
}

static void rule_expression_free(struct rule_expression *expr)
{
	LASSERT(expr->re_field >= RULE_FIELD_UID &&
		expr->re_field < RULE_FIELD_MAX);
	switch (expr->re_field) {
	case RULE_FIELD_UID:
	case RULE_FIELD_GID:
	case RULE_FIELD_PROJID:
		rule_id_list_free(expr);
		break;
	case RULE_FIELD_FNAME:
		rule_fname_list_free(expr);
		break;
	case RULE_FIELD_SIZE:
		rule_size_list_free(expr);
		break;
	default:
		LBUG();
	}
	OBD_FREE_PTR(expr);
}

static void rule_conjunction_free(struct rule_conjunction *conjunction)
{
	struct rule_expression *expression, *n;

	LASSERT(list_empty(&conjunction->rc_linkage));
	list_for_each_entry_safe(expression, n,
				 &conjunction->rc_expressions,
				 re_linkage) {
		list_del_init(&expression->re_linkage);
		rule_expression_free(expression);
	}
	OBD_FREE_PTR(conjunction);
}

static void rule_conds_free(struct list_head *cond_list)
{
	struct rule_conjunction *conjunction, *n;

	list_for_each_entry_safe(conjunction, n, cond_list, rc_linkage) {
		list_del_init(&conjunction->rc_linkage);
		rule_conjunction_free(conjunction);
	}
}

void cfs_rule_fini(struct cfs_rule *rule)
{
	if (!list_empty(&rule->rl_conds))
		rule_conds_free(&rule->rl_conds);

	if (rule->rl_conds_str != NULL) {
		OBD_FREE(rule->rl_conds_str, strlen(rule->rl_conds_str) + 1);
		rule->rl_conds_str = NULL;
	}
}
EXPORT_SYMBOL(cfs_rule_fini);

/* Rule Parsing */
#define RULE_DISJUNCTION_DELIM		(',')
#define RULE_CONJUNCTION_DELIM		('&')
#define RULE_EXPRESSION_DELIM_EQ	('=')
#define RULE_EXPRESSION_DELIM_LT	('<')
#define RULE_EXPRESSION_DELIM_GT	('>')

static int
rule_fname_list_add(struct cfs_lstr *id, struct list_head *fname_list)
{
	struct rule_match_fname *fname;

	OBD_ALLOC_PTR(fname);
	if (fname == NULL)
		return -ENOMEM;

	OBD_ALLOC(fname->rmf_name, id->ls_len + 1);
	if (fname->rmf_name == NULL) {
		CFS_FREE_PTR(fname);
		return -ENOMEM;
	}

	memcpy(fname->rmf_name, id->ls_str, id->ls_len);
	list_add_tail(&fname->rmf_linkage, fname_list);
	return 0;
}

static int
rule_fname_list_parse(char *str, int len, struct rule_expression *expr)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	ENTRY;

	if (expr->re_opc != RULE_FIELD_OP_EQ)
		RETURN(-EINVAL);

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(&expr->re_cond);
	while (src.ls_str) {
		rc = cfs_gettok(&src, ' ', &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = rule_fname_list_add(&res, &expr->re_cond);
		if (rc)
			break;
	}
	if (rc)
		rule_fname_list_free(expr);
	RETURN(rc);
}

static int
rule_id_list_parse(char *str, int len, struct rule_expression *expr)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	ENTRY;

	if (expr->re_field != RULE_FIELD_UID &&
	    expr->re_field != RULE_FIELD_GID &&
	    expr->re_field != RULE_FIELD_PROJID)
		RETURN(-EINVAL);

	if (expr->re_opc >= RULE_FIELD_OP_MAX)
		RETURN(-EINVAL);

	src.ls_str = str;
	src.ls_len = len;

	INIT_LIST_HEAD(&expr->re_cond);

	while (src.ls_str) {
		struct rule_match_id *id;
		__u32 id_val;

		if (cfs_gettok(&src, ' ', &res) == 0)
			GOTO(out, rc = -EINVAL);

		if (!cfs_str2num_check(res.ls_str, res.ls_len,
				       &id_val, 0, (u32)~0U))
			GOTO(out, rc = -EINVAL);

		OBD_ALLOC_PTR(id);
		if (id == NULL)
			GOTO(out, rc = -ENOMEM);

		id->rmi_id = id_val;
		list_add_tail(&id->rmi_linkage, &expr->re_cond);
	}
out:
	if (rc)
		rule_id_list_free(expr);
	RETURN(rc);
}

static int
rule_expr_id_parse(char *str, int len, struct rule_expression *expr)
{
	int rc = 0;

	if (expr->re_opc == RULE_FIELD_OP_EQ)
		rc = rule_id_list_parse(str, len, expr);
	else if (!cfs_str2num_check(str, len, &expr->re_id, 0, (u32)~0U))
		rc = -EINVAL;

	return rc;
}

static int
rule_size_list_parse(char *str, int len, struct rule_expression *expr)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	ENTRY;

	if (expr->re_field != RULE_FIELD_SIZE)
		RETURN(-EINVAL);

	if (expr->re_opc >= RULE_FIELD_OP_MAX)
		RETURN(-EINVAL);

	src.ls_str = str;
	src.ls_len = len;

	INIT_LIST_HEAD(&expr->re_cond);

	while (src.ls_str) {
		struct rule_match_size *sz;
		__u64 sz_val;

		if (cfs_gettok(&src, ' ', &res) == 0)
			GOTO(out, rc = -EINVAL);

		rc = sysfs_memparse(res.ls_str, res.ls_len, &sz_val, "MiB");
		if (rc < 0)
			GOTO(out, rc = rc);

		OBD_ALLOC_PTR(sz);
		if (sz == NULL)
			GOTO(out, rc = -ENOMEM);

		sz->rms_size = sz_val;
		list_add_tail(&sz->rms_linkage, &expr->re_cond);
	}
out:
	if (rc)
		rule_id_list_free(expr);
	RETURN(rc);
}

static int
rule_expr_size_parse(char *str, int len, struct rule_expression *expr)
{
	if (expr->re_opc == RULE_FIELD_OP_EQ)
		return rule_size_list_parse(str, len, expr);
	else
		return sysfs_memparse(str, len, &expr->re_size, "MiB");
}

static inline bool
rule_check_field(struct cfs_lstr *field, char *str)
{
	int len = strlen(str);

	return (field->ls_len == len &&
		strncmp(field->ls_str, str, len) == 0);
}

static inline char
rule_get_opcode_delim(enum rule_field_op opc)
{
	switch (opc) {
	case RULE_FIELD_OP_EQ:
		return RULE_EXPRESSION_DELIM_EQ;
	case RULE_FIELD_OP_LT:
		return RULE_EXPRESSION_DELIM_LT;
	case RULE_FIELD_OP_GT:
		return RULE_EXPRESSION_DELIM_GT;
	default:
		LBUG();
	}
}

static enum rule_field_op
rule_get_field_opcode(struct cfs_lstr *src, struct cfs_lstr *field)
{
	struct cfs_lstr tmp;
	int rc;
	int i;

	ENTRY;

	for (i = RULE_FIELD_OP_EQ; i < RULE_FIELD_OP_MAX; i++) {
		tmp = *src;
		rc = cfs_gettok(&tmp, rule_get_opcode_delim(i), field);
		if (rc > 0 && tmp.ls_str != NULL) {
			src->ls_str = tmp.ls_str;
			src->ls_len = tmp.ls_len;
			RETURN(i);
		}
	}

	RETURN(RULE_FIELD_OP_INV);
}

static int
rule_expression_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct rule_expression *expr;
	enum rule_field_op opc;
	struct cfs_lstr field;
	int rc;

	opc = rule_get_field_opcode(src, &field);
	if (opc == RULE_FIELD_OP_INV)
		return -EINVAL;

	if (src->ls_len <= 2 || src->ls_str[0] != '{' ||
	    src->ls_str[src->ls_len - 1] != '}')
		return -EINVAL;

	OBD_ALLOC_PTR(expr);
	if (expr == NULL)
		return -ENOMEM;

	/* Skip '{' and '}' */
	src->ls_str++;
	src->ls_len -= 2;

	expr->re_opc = opc;
	if (rule_check_field(&field, "uid")) {
		expr->re_field = RULE_FIELD_UID;
		if (rule_expr_id_parse(src->ls_str, src->ls_len, expr) < 0)
			GOTO(out, rc = -EINVAL);
	} else if (rule_check_field(&field, "gid")) {
		expr->re_field = RULE_FIELD_GID;
		if (rule_expr_id_parse(src->ls_str, src->ls_len, expr) < 0)
			GOTO(out, rc = -EINVAL);
	} else if (rule_check_field(&field, "projid")) {
		expr->re_field = RULE_FIELD_PROJID;
		if (rule_expr_id_parse(src->ls_str, src->ls_len, expr) < 0)
			GOTO(out, rc = -EINVAL);
	} else if (rule_check_field(&field, "size")) {
		expr->re_field = RULE_FIELD_SIZE;
		if (rule_expr_size_parse(src->ls_str, src->ls_len, expr) < 0)
			GOTO(out, rc = -EINVAL);
	} else if (rule_check_field(&field, "fname")) {
		if (opc != RULE_FIELD_OP_EQ)
			GOTO(out, rc = -EINVAL);

		expr->re_field = RULE_FIELD_FNAME;
		if (rule_fname_list_parse(src->ls_str, src->ls_len, expr) < 0)
			GOTO(out, rc = -EINVAL);
	} else {
		GOTO(out, rc = -EINVAL);
	}

	list_add_tail(&expr->re_linkage, cond_list);
	return 0;
out:
	OBD_FREE_PTR(expr);
	return rc;
}

static int
rule_conjunction_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct rule_conjunction *conjunction;
	struct cfs_lstr expr;
	int rc = 0;

	OBD_ALLOC_PTR(conjunction);
	if (conjunction == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&conjunction->rc_expressions);
	list_add_tail(&conjunction->rc_linkage, cond_list);

	while (src->ls_str) {
		rc = cfs_gettok(src, RULE_CONJUNCTION_DELIM, &expr);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = rule_expression_parse(&expr,
					   &conjunction->rc_expressions);
		if (rc)
			break;
	}
	return rc;
}

static int rule_conds_parse(char *str, int len, struct list_head *cond_list)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	src.ls_str = str;
	src.ls_len = len;
	while (src.ls_str) {
		rc = cfs_gettok(&src, RULE_DISJUNCTION_DELIM, &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = rule_conjunction_parse(&res, cond_list);
		if (rc)
			break;
	}
	return rc;
}

int cfs_rule_parse_init(struct cfs_rule *rule, const char *id)
{
	int rc;

	INIT_LIST_HEAD(&rule->rl_conds);
	OBD_ALLOC(rule->rl_conds_str, strlen(id) + 1);
	if (rule->rl_conds_str == NULL)
		return -ENOMEM;

	memcpy(rule->rl_conds_str, id, strlen(id));
	rc = rule_conds_parse(rule->rl_conds_str, strlen(rule->rl_conds_str),
			      &rule->rl_conds);
	if (rc)
		cfs_rule_fini(rule);

	return rc;
}
EXPORT_SYMBOL(cfs_rule_parse_init);

/* Rule Matching */
static int
rule_id_list_match(struct list_head *id_list, __u32 id_val)
{
	struct rule_match_id *id;

	list_for_each_entry(id, id_list, rmi_linkage) {
		if (id->rmi_id == id_val)
			return 1;
	}
	return 0;
}

static bool
cfs_match_wildcard(const char *pattern, const char *content)
{
	if (*pattern == '\0' && *content == '\0')
		return true;

	if (*pattern == '*' && *(pattern + 1) != '\0' && *content == '\0')
		return false;

	while (*pattern == *content) {
		pattern++;
		content++;
		if (*pattern == '\0' && *content == '\0')
			return true;

		if (*pattern == '*' && *(pattern + 1) != '\0' &&
		    *content == '\0')
			return false;
	}

	if (*pattern == '*')
		return (cfs_match_wildcard(pattern + 1, content) ||
			cfs_match_wildcard(pattern, content + 1));

	return false;
}

static int
rule_fname_list_match(struct list_head *fname_list, const char *name)
{
	struct rule_match_fname *fname;

	list_for_each_entry(fname, fname_list, rmf_linkage) {
		if (cfs_match_wildcard(fname->rmf_name, name))
			return 1;
	}
	return 0;
}

static int
rule_expr_id_match(struct rule_expression *expr, __u32 id)
{
	switch (expr->re_opc) {
	case RULE_FIELD_OP_EQ:
		return rule_id_list_match(&expr->re_cond, id);
	case RULE_FIELD_OP_LT:
		return id < expr->re_id;
	case RULE_FIELD_OP_GT:
		return id > expr->re_id;
	default:
		return 0;
	}
}

static int
rule_size_list_match(struct list_head *id_list, __u64 sz_val)
{
	struct rule_match_size *sz;

	list_for_each_entry(sz, id_list, rms_linkage) {
		if (sz->rms_size == sz_val)
			return 1;
	}
	return 0;
}

static int
rule_expr_size_match(struct rule_expression *expr, __u64 sz)
{
	switch (expr->re_opc) {
	case RULE_FIELD_OP_EQ:
		return rule_size_list_match(&expr->re_cond, sz);
	case RULE_FIELD_OP_LT:
		return sz < expr->re_size;
	case RULE_FIELD_OP_GT:
		return sz > expr->re_size;
	default:
		return 0;
	}
}

static int
rule_expression_match(struct rule_expression *expr, struct cfs_matcher *matcher)
{
	switch (expr->re_field) {
	case RULE_FIELD_UID:
		return rule_expr_id_match(expr, matcher->mc_uid);
	case RULE_FIELD_GID:
		return rule_expr_id_match(expr, matcher->mc_gid);
	case RULE_FIELD_PROJID:
		return rule_expr_id_match(expr, matcher->mc_projid);
	case RULE_FIELD_SIZE:
		return rule_expr_size_match(expr, matcher->mc_size);
	case RULE_FIELD_FNAME:
		return rule_fname_list_match(&expr->re_cond,
					    matcher->mc_name->name);
	default:
		return 0;
	}
}

static int
rule_conjunction_match(struct rule_conjunction *conjunction,
		       struct cfs_matcher *matcher)
{
	struct rule_expression *expr;
	int matched;

	list_for_each_entry(expr, &conjunction->rc_expressions, re_linkage) {
		matched = rule_expression_match(expr, matcher);
		if (!matched)
			return 0;
	}

	return 1;
}

int cfs_rule_match(struct cfs_rule *rule, struct cfs_matcher *matcher)
{
	struct rule_conjunction *conjunction;
	int matched;

	list_for_each_entry(conjunction, &rule->rl_conds, rc_linkage) {
		matched = rule_conjunction_match(conjunction, matcher);
		if (matched)
			return 1;
	}

	return 0;
}
EXPORT_SYMBOL(cfs_rule_match);
