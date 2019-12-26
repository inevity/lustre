#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# exit on error
set -e
set +o monitor

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/utils:$PATH:/sbin:/usr/sbin

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

ENABLE_PROJECT_QUOTAS=${ENABLE_PROJECT_QUOTAS:-true}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

MULTIOP=${MULTIOP:-multiop}
OPENFILE=${OPENFILE:-openfile}
MMAP_CAT=${MMAP_CAT:-mmap_cat}
MOUNT_2=${MOUNT_2:-"yes"}
FAIL_ON_ERROR=false

# script only handles up to 10 MDTs (because of MDT_PREFIX)
[ $MDSCOUNT -gt 9 ] &&
	error "script cannot handle more than 9 MDTs, please fix" && exit

check_and_setup_lustre

if [[ "$MDS1_VERSION" -lt $(version_code 2.13.50) ]]; then
	skip "Need MDS version at least 2.13.50"
fi

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS
if getent group nobody; then
	GROUP=nobody
elif getent group nogroup; then
	GROUP=nogroup
else
	error "No generic nobody group"
fi

build_test_filter

# if there is no CLIENT1 defined, some tests can be ran on localhost
CLIENT1=${CLIENT1:-$HOSTNAME}
# if CLIENT2 doesn't exist then use CLIENT1 instead
# All tests should use CLIENT2 with MOUNT2 only therefore it will work if
# $CLIENT2 == CLIENT1
# Exception is the test which need two separate nodes
CLIENT2=${CLIENT2:-$CLIENT1}

# Temporal soluation to make all files create on MDT0.
$LFS setdirstripe -D -i 0 $MOUNT

cleanup_wbc()
{
	$LCTL set_param llite.*.wbc.conf=disable ||
		error "failed to disable WBC"
}

wbc_conf_show()
{
	$LCTL get_param llite.*.wbc.conf
}

setup_wbc()
{
	local conf="$1"

	stack_trap "cleanup_wbc" EXIT
	if [ -n "$conf" ]; then
		$LCTL set_param llite.*.wbc.conf="conf $conf" ||
			error "failed to conf WBC: conf $conf"
	else
		$LCTL set_param llite.*.wbc.conf=enable ||
			error "failed to enable WBC"
	fi
	wbc_conf_show
}

get_wbc_flags() {
	local file=$1
	local st

	st=$($LFS wbc state $file)
	[[ $? == 0 ]] || error "$LFS wbc state $file failed"

	st=$(echo $st | cut -f 3 -d" " | tr -d "()," )
	echo $st
}

check_wbc_flags() {
	local file=$1
	local flags=$2
	local prefix=$3

	local st=$(get_wbc_flags "$prefix$file")

	[[ $st == $flags ]] || error "wbc flags on $3$file are $st != $flags"
}

check_fileset_wbc_flags() {
	local fileset="$1"
	local flags=$2
	local prefix=$3
	local file

	[ -n "$prefix" ] && prefix="$prefix/"
	for file in $fileset; do
		check_wbc_flags $file $flags $prefix
	done
}

check_mdt_fileset_exist() {
	# skip ZFS backend
	[ "$mds1_FSTYPE" == "ldiskfs" ] || return 0

	local mdtdev=$(mdsdevname ${SINGLEMDS//mds/})
	local fileset="$1"
	local expected=$2

	do_facet mds1 "
for file in $fileset; do
	debugfs -c -R \\\"stat ROOT/\\\$file\\\" $mdtdev | grep 'Inode:';
	if [ \\\$? -ne $expected ] ; then
		exit 1;
	fi;
done;
exit 0;"
	return $?
}

wait_wbc_sync_state() {
	local file=$1
	local client=${2:-$HOSTNAME}\
	local cmd="$LFS wbc state $file"

	cmd+=" | grep -E -c 'state: .*(none|sync)'"
	echo $cmd
	wait_update --verbose $client "$cmd" "1" 10 ||
		error "$file is not synced"
}

test_1() {
	local file1="$tdir/file1"
	local dir1="$tdir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$tdir/file3"
	local file4="$tdir/file4"
	local file5="$tdir/file5"
	local file6="$tdir/file6"

	setup_wbc

	# WBC flags:
	# 0x00000000: not in WBC
	# 0x0000000f: in Root(R) | Protected(P) | Sync(S) | Complete(P) state
	# 0x00000005: in Protected(P)| Complete(C) state
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$LFS wbc state $DIR/$tdir
	check_wbc_flags $DIR/$tdir "0x0000000f"
	echo "QQQQQ" > $DIR/$file1 || error "echo $DIR/$file1 failed"
	mkdir $DIR/$dir1 || error "mkdir $DIR/$dir1 failed"
	mkdir $DIR/$dir2 || error "mkdir $DIR/$dir2 failed"
	dd if=/dev/zero of=$DIR/$file2 bs=4k count=2 conv=notrunc ||
		error "failed to dd $DIR/$file2"
	touch $DIR/$file3 || error "touch $DIR/$file3 failed"
	dd if=/dev/zero of=$DIR/$file4 bs=4097 count=2 conv=notrunc ||
		error "failed to dd $DIR/$file4"
	# TODO: Verify the correctness for a file with multiple stripes
	# after add lfs setstripe support for WBC caching file.
	dd if=/dev/zero of=$DIR/$file5 bs=1M count=2 conv=notrunc ||
		error "failed to dd $DIR/$file5"
	dd if=/dev/zero of=$DIR/$file6 bs=1048579 count=2 conv=notrunc ||
		error "failed to dd $DIR/$file6"

	local fileset="$file1 $file2 $dr1 $dir2 $file3 $file4 $file5 $file6"

	check_mdt_fileset_exist "$fileset" 1 ||
		error "'$filelist' should not exist under ROOT on MDT "
	check_fileset_wbc_flags "$fileset" "0x00000005" $DIR

	# Flush directories level by level when WBC EX lock is revoking
	echo "stat $DIR2/$tdir"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	fileset="$file1 $dir1 $file3 $file4 $file5 $file6"
	check_fileset_wbc_flags "$fileset" "0x0000000f" $DIR
	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist under ROOT on MDT"
	fileset="$file2 $dir2"
	check_fileset_wbc_flags "$fileset" "0x00000005" $DIR
	check_mdt_fileset_exist "$filelist" 1 ||
		error "'$filelist' should not exist under ROOT on MDT"

	echo "stat $DIR2/$dir1"
	stat $DIR2/$dir1 || error "stat $DIR2/$dir1 failed"
	fileset="$file2 $dir2"
	# 0x0000000f: Root(R) | Sync(S) | Protect(P) | Complete(C).
	check_fileset_wbc_flags "$fileset" "0x0000000f" $DIR
	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist under ROOT on MDT"

	$CHECKSTAT -s 6 $DIR/$file1 ||
		error "$DIR/$file1 size wrong, expected 6"
	$CHECKSTAT -s 8192 $DIR/$file2 ||
		error "$DIR/$file2 size wrong, expected 8192"
	$CHECKSTAT -s 0 $DIR/$file3 ||
		error "$DIR/$file1 size wrong, expected 0"
	$CHECKSTAT -s 8194 $DIR/$file4 ||
		error "$DIR/$file4 size wrong, expected 6"
	$CHECKSTAT -s 6 $DIR2/$file1 ||
		error "$DIR2/$file1 size wrong, expected 6"
	$CHECKSTAT -s 8192 $DIR2/$file2 ||
		error "$DIR2/$file2 size wrong, expected 8192"
	$CHECKSTAT -s 0 $DIR2/$file3 ||
		error "$DIR2/$file1 size wrong, expected 0"
	$CHECKSTAT -s 8194 $DIR2/$file4 ||
		error "$DIR2/$file4 size wrong, expected 6"
	$CHECKSTAT -s 2097152 $DIR2/$file5 ||
		error "$DIR2/$file5 size wrong, expected 2097152"
	$CHECKSTAT -s 2097158 $DIR2/$file6 ||
		error "$DIR2/$file6 size wrong, expected 2097158"
}
run_test 1 "Basic test for WBC with LAZY flush mode"

test_2() {
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

	setup_wbc

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000005"
	oldmd5=$(md5sum $file | awk '{print $1}')
	newmd5=$(md5sum $file2 | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	check_fileset_wbc_flags "$dir $file" "0x00000000"

	rm -rf $dir || error "rm $dir failed"
	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000005"
	oldmd5=$(md5sum $file | awk '{print $1}')
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_wbc_flags $dir "0x00000000"
	check_wbc_flags $file "0x0000000f"
	newmd5=$(md5sum $file2 | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	check_fileset_wbc_flags "$dir $file" "0x00000000"

	rm -rf $dir || error "rm $dir failed"
	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	echo "QQQQQ" > $file || error "write $file failed"
	check_wbc_flags $file "0x00000005"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_wbc_flags $dir "0x00000000"
	check_wbc_flags $file "0x0000000f"
	$MULTIOP $file2 or1c || error "read $file2 failed"
	rm -rf $dir || error "rm $dir failed"

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	echo "QQQQQ" > $file || error "write $file failed"
	check_wbc_flags $file "0x00000005"
	$MULTIOP $file2 or1c || error "read $file2 failed"
}
run_test 2 "Verify remote read works correctly"

test_3() {
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

	setup_wbc

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000005"
	oldmd5=$(md5sum $file | awk '{print $1}')
	$CHECKSTAT -s 1049600 $file || error "$file size wrong"
	stat $file2 || error "stat $file2 failed"
	check_wbc_flags $DIR/$tdir "0x00000000"
	check_wbc_flags $file "0x00000000"
	newmd5=$(md5sum $file2 | awk '{print $1}')
	$CHECKSTAT -s 1049600 $file2 || error "$file size wrong"
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"

	rm -rf $dir || error "rm $dir failed"
	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000005"
	oldmd5=$(md5sum $file | awk '{print $1}')
	$CHECKSTAT -s 1049600 $file || error "$file size wrong"
	$MULTIOP $file2 oc || error "stat $file2 failed"
	check_wbc_flags $DIR/$tdir "0x00000000"
	check_wbc_flags $file "0x0000000f"
	newmd5=$(md5sum $file2 | awk '{print $1}')
	check_wbc_flags $file "0x00000000"
	$CHECKSTAT -s 1049600 $file2 || error "$file size wrong"
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
}
run_test 3 "Remote read for WBC cached regular file with holes"

test_4() {
	local dir11="$DIR/$tdir"
	local dir21="$DIR2/$tdir"
	local file11="$dir11/$tfile"
	local file21="$dir21/$tfile"
	local dir12="$dir11/dir2"
	local dir22="$dir21/dir2"
	local file12="$dir12/file2"
	local file22="$dir22/file2"

	setup_wbc

	mkdir $dir11 || error "mkdir $dir11 failed"
	rmdir $dir21 || error "rmdir $dir21 failed"

	mkdir $dir11 || error "mkdir $dir11 failed"
	echo "QQQQQ" > $file11 || error "wirte $file11 failed"
	unlink $file21 || error "unlink $file21 failed"
	rmdir $dir21 || error "unlink $dir21 failed"

	mkdir $dir11 || error "mkdir $dir11 failed"
	echo "QQQQ" > $file11 || error "write $file11 failed"
	$MULTIOP $file11 oc || error "open/close $file22 failed"
	unlink $file21 || error "unlink $file21 failed"
	rmdir $dir21 || error "unlink $dir21 failed"

	mkdir $dir11 || error "mkdir $dir11 failed"
	mkdir $dir12 || error "mkdir $dir12 failed"
	echo "QQQQQ" > $file12 || error "write $file12 failed"
	unlink $file22 || error "unlink $file22 failed"
	rmdir $dir22 || error "rmdir $dir22 failed"
	rmdir $dir21 || error "rmdir $dir21 failed"

	mkdir $dir11 || error "mkdir $dir11 failed"
	check_wbc_flags $dir11 "0x0000000f"
	echo "QQQQ" > $file11 || error "write $file11 failed"
	mkdir $dir12 || error "mkdir $dir12 failed"
	echo "QQQQQQ" > $file12 || error "write $file12 failed"
	check_fileset_wbc_flags "$file11 $dir12 $file12" "0x00000005"
	unlink $file21 || error "unlink $file21 failed"
	stat $file11 && error "$file11 should be deleted"
	unlink $file22 || error "unlink $file22 failed"
	stat $file12 && error "$file12 should be deleted"
	rmdir $dir22 || error "rmdir $dir22 failed"
	stat $dir12 && error "$dir12 should be delete"
	rmdir $dir21 || error "rmdir $dir21 failed"
	stat $dir11 && error "$dir11 should be deleted"

	mkdir $dir11 || error "mkdir $dir11 failed"
	check_wbc_flags $dir11 "0x0000000f"
	mkdir $dir12 || error "mkdir $dir12 failed"
	rmdir $dir22 || error "rm $dir22 failed"
	stat $dir12 && error "$dir12 should be deleted"
	rmdir $dir21 || error "rm $dir21 failed"
	stat $dir11 && error "$dir11 should be deleted"

	mkdir $dir11 || error "mkdir $dir11 failed"
	check_wbc_flags $dir11 "0x0000000f"
	mkdir $dir12 || error "mkdir $dir12 failed"
	echo "QQQQQQ" > $file12 || error "write $file12 failed"
	unlink $file22 || error "unlink $file22 failed"
	stat $file12 && error "$file12 should be deleted"
	check_fileset_wbc_flags "$dir11 $dir12" "0x00000000"
}
run_test 4 "Verify unlink() works correctly"

test_5() {
	local dir="$DIR/$tdir"
	local path="indirect/bar"
	local parent=$(dirname $path)

	mkdir $dir || error "mkdir $dir failed"
	cd $dir
	stat $parent
	mkdir $parent || error "mkdir $parent failed"
	mkdir $path || error "mkdir $dir/$path failed"
}
run_test 5 "Hanle -ENOENT lookup failure correctly"

test_6() {
	local file1="$tdir/file1"
	local dir1="$tdir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local interval=$(sysctl -n vm.dirty_writeback_centisecs)
	local expire=$(sysctl -n vm.dirty_expire_centisecs)
	local oldmd5
	local newmd5

	setup_wbc "cache_mode=memfs flush_mode=aging_drop"
	echo "dirty_writeback_centisecs: $interval"
	interval=$((interval + 100))
	stack_trap "sysctl -w vm.dirty_expire_centisecs=$expire" EXIT
	sysctl -w vm.dirty_expire_centisecs=$interval

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$LFS wbc state $DIR/$tdir
	mkdir $DIR/$dir1 || error "mkdir $DIR/$dir1 failed"
	mkdir $DIR/$dir2 || error "mkdir $DIR/$dir2 failed"
	echo "QQQQQ" > $DIR/$file1 || error "write $DIR/$file1 failed"
	dd if=/dev/zero of=$DIR/$file2 seek=1k bs=1k count=1 ||
		error "failed to write $DIR/$file2"
	oldmd5=$(md5sum $DIR/$file2 | awk '{print $1}')
	echo "KKKKK" > $DIR/$file3 || error "write  $DIR/$file3 failed"

	local fileset="$file1 $dir1 $file2 $dir2 $file3"

	ls -R $DIR/$tdir
	check_fileset_wbc_flags "$fileset" "0x00000005" $DIR
	sleep $((interval / 100))

	wait_wbc_sync_state $DIR/$file3
	check_fileset_wbc_flags "$fileset" "0x00000000" $DIR
	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist on MDT"

	remount_client $MOUNT || error "failed to remount client $MOUNT"
	newmd5=$(md5sum $DIR/$file2 | awk '{print $1}')
	[ "$newmd5" == "$oldmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
}
run_test 6 "Verify aging flush mode"

test_7() {
	local dir="$DIR/$tdir"
	local dir1="$dir/dir1"
	local file1="$dir/file1"
	local fileset="$dir1 $file1"
	local expected="400"
	local accd
	local accf

	setup_wbc

	mkdir $dir || error "mkdir $dir failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x00000005"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	chmod $expected $dir1 || error "chmod $expected $dir1 failed"
	chmod $expected $file1 || error "chmod $expected $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	rm -rf $dir || error "rm $dir failed"

	mkdir $dir || error "mkdir $dir failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x00000005"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	accd=$(stat -c %a $dir1)
	accf=$(stat -c %a $file1)
	echo "$dir1 access rights: $accd"
	echo "$file1 access rights: $accf"
	chmod $expected $dir1 || error "chmod $expected $dir1 failed"
	chmod $expected $file1 || error "chmod $expected $file1 failed"
	stat $DIR2/$tdir/dir1 || error "stat $DIR2/$tdir/dir1 failed"
	stat $DIR2/$tdir/file1 || error "stat $DIR2/$tdir/file1 failed"
	accd=$(stat -c %a $dir1)
	accf=$(stat -c %a $file1)
	echo "$dir1 access rights: $accd"
	echo "$file1 access rights: $accf"
	[ $accd == $expected ] ||
		error "$dir1 access rights: $accd, expect $expected"
	[ $accf == $expected ] ||
		error "$file1 access rights: $accf, expect $expected"
}
run_test 7 "setattr() on the root WBC file"

log "cleanup: ======================================================"

# kill and wait in each test only guarentee script finish, but command in script
# like 'rm' 'chmod' may still be running, wait for all commands to finish
# otherwise umount below will fail
[ "$(mount | grep $MOUNT2)" ] && wait_update $HOSTNAME "fuser -m $MOUNT2" "" ||
	true

complete $SECONDS
check_and_cleanup_lustre
exit_status
