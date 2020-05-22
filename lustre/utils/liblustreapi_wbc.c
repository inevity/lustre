/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * LGPL version 2.1 or (at your discretion) any later version.
 * LGPL version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * lustre/utils/liblustreapi_wbc.c
 *
 * lustreapi library for Metadata Writeback Caching (WBC).
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_fid.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include "lustreapi_internal.h"

/**
 * Return the current WBC state related to a file.
 *
 * \param fd    File handle.
 * \param state WBC state info.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_wbc_state_get_fd(int fd, struct lu_wbc_state *state)
{
	int rc;

	rc = ioctl(fd, LL_IOC_WBC_STATE, state);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	return rc;
}

/**
 * Return the current WBC state related to file pointed by a path.
 *
 * see llapi_wbc_state_get_fd() for args use and return
 */
int llapi_wbc_state_get(const char *path, struct lu_wbc_state *state)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	rc = llapi_wbc_state_get_fd(fd, state);

	close(fd);
	return rc;
}

/**
 * Unreserve the given file from WBC.
 *
 * \param fd			File handle.
 * \param all_same_level	Whether unreserve all siblings.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_wbc_unreserve_file_fd(int fd, __u32 unrsv_siblings)
{
	struct lu_wbc_unreserve unrsv;
	int rc;

	unrsv.wbcu_unrsv_siblings = unrsv_siblings;
	rc = ioctl(fd, LL_IOC_WBC_UNRESERVE, &unrsv);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	return rc;
}

/**
 * Unreserve the given file pointed by \a path from WBC.
 *
 * see llapi_wbc_unreserve_file_fd() for args use and return.
 */
int llapi_wbc_unreserve_file(const char *path, __u32 unrsv_siblings)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	rc = llapi_wbc_unreserve_file_fd(fd, unrsv_siblings);

	close(fd);
	return rc;
}
