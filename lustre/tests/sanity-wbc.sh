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
#$LFS setdirstripe -D -i 0 $MOUNT

cleanup_wbc()
{
	$LCTL set_param llite.*.wbc.conf=disable ||
		error "failed to disable WBC"
}

clear_wbc()
{
	$LCTL set_param llite.*.wbc.conf=clear ||
		error "failed to clear WBC"
}

wbc_conf_show()
{
	local mnt=${1:-$MOUNT}

	$LCTL get_param llite.$($LFS getname $mnt | awk '{print $1}').wbc.conf
}

setup_wbc()
{
	local conf="$1"
	local mnt=${2:-$MOUNT}
	local fsuuid=$($LFS getname $mnt | awk '{print $1}')

	stack_trap "cleanup_wbc" EXIT
	if [ -n "$conf" ]; then
		$LCTL set_param llite.$fsuuid.wbc.conf="conf $conf" ||
			error "failed to conf WBC: conf $conf"
	else
		$LCTL set_param llite.$fsuuid.wbc.conf=enable ||
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

	[[ $st == $flags ]] || error "wbc flags on $file are $st != $flags"
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

	local fileset="$1"
	local expected=$2
	local path=$DIR/$tdir
	local mds_index=$(($($LFS getstripe -m $path) + 1))
	local mdtdev=$(mdsdevname $mds_index)
	local fset=""
	local root
	local fid

	if [ $mds_index == 1 ]; then
		root="/ROOT"
	else
		fid=$(path2fid $path)
		root="/REMOTE_PARENT_DIR/$fid"
		for file in $fileset; do
			fpath=${file#*/}
			fset+="$fpath "
		done
		fileset=$fset
	fi

	echo "root: $root mds_index: $mds_index"
	echo "FSET: $fileset"
	do_facet mds$mds_index "
for file in $fileset; do
	debugfs -c -R \\\"stat $root/\\\$file\\\" $mdtdev | grep 'Inode:';
	if [ \\\$? -ne $expected ] ; then
		exit 1;
	fi;
done;
exit 0;"
	return $?
}

wait_wbc_sync_state() {
	local file=$1
	local client=${2:-$HOSTNAME}
	local cmd="$LFS wbc state $file"

	cmd+=" | grep -E -c 'state: .*(none|sync)'"
	echo $cmd
	wait_update --verbose $client "$cmd" "1" 50 ||
		error "$file is not synced"
}

check_wbc_flushed() {
	local file=$1
	local sync=$($LFS wbc state $file | grep -E -c 'state: .*(none|sync)')

	[ $sync == "1" ] || error "$file is not flushed to MDT"
}

check_fileset_wbc_flushed() {
	local fileset="$1"
	local file

	for file in $fileset; do
		check_wbc_flushed $file
	done
}

check_wbc_inode_reserved() {
	local file=$1
	local expected=$2
	local reserved=$($LFS wbc state $file | grep -E -c 'state: .*reserved')

	[ $reserved == "$expected" ] ||
		error "$file Reserved(E) state: $reserved, expected $expected"
}

check_fileset_inode_reserved() {
	local fileset="$1"
	local expected=$2
	local file

	for file in $fileset; do
		check_wbc_inode_reserved $file $expected
	done
}

check_wbc_inode_complete() {
	local file=$1
	local expected=$2
	local comp=$($LFS wbc state $file | grep -E -c 'state: .*complete')

	[ $comp == "$expected" ] ||
		error "$file Complete(C) state: $comp, expected $expected"
}

wait_wbc_uptodate() {
	local file=$1
	local client=${2:-$HOSTNAME}
	local uptodate="$LFS wbc state $file"

	cmd+=" | grep -E -c 'state: .*(none|uptodate)'"

	echo $cmd
	wait_update --verbose $client "$cmd" "1" 50 ||
		error "$file is not UPTODATE"
}

check_wbc_uptodate() {
	local file=$1
	local uptodate=$($LFS wbc state $file |
			grep -E -c 'state: .*(none|uptodate')

	[ $uptodate == "1" ] || error "$file is not UPTODATE"
}

check_fileset_wbc_uptodate() {
	local fileset="$1"
	local file

	for file in $fileset; do
		check_wbc_uptodate $file
	done
}

reset_kernel_writeback_param() {
	local interval=$(sysctl -n vm.dirty_writeback_centisecs)
	local expire=$(sysctl -n vm.dirty_expire_centisecs)

	interval=$((interval + 100))
	stack_trap "sysctl -w vm.dirty_expire_centisecs=$expire" EXIT
	sysctl -w vm.dirty_expire_centisecs=$interval
}

flush_mode_lock_keep() {
	wbc_conf_show | grep -c -E "flush_mode: (aging|lazy)_keep" &> /dev/null
}

flush_mode_lock_drop() {
	wbc_conf_show | grep -c -E "flush_mode: (aging|lazy)_drop" &> /dev/null
}

get_free_inodes() {
	wbc_conf_show | grep "inodes_free:" | awk '{print $2}'
}

get_free_pages() {
	wbc_conf_show | grep "pages_free:" | awk '{print $2}'
}

test_1_base() {
	local flush_mode=$1
	local file1="$tdir/file1"
	local dir1="$tdir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$tdir/file3"
	local file4="$tdir/file4"
	local file5="$tdir/file5"
	local file6="$tdir/file6"

	setup_wbc "flush_mode=$flush_mode"

	# WBC flags:
	# 0x00000000: not in WBC
	# 0x0000000f: Root(R) | Protected(P) | Sync(S) | Complete(P) state
	# 0x00000015: Protected(P)| Complete(C) | Reserved(E) state
	# 0x00000017: Protected(P)| Complete(C) | Sync(S) | Reserved(E) state
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
		error "'$filelist' should not exist under ROOT on MDT"
	check_fileset_wbc_flags "$fileset" "0x00000015" $DIR

	# Flush directories level by level when WBC EX lock is revoking
	echo "stat $DIR2/$tdir"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	fileset="$file1 $dir1 $file3 $file4 $file5 $file6"
	check_fileset_wbc_flags "$fileset" "0x0000000f" $DIR

	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist under ROOT on MDT"
	fileset="$file2 $dir2"
	check_fileset_wbc_flags "$fileset" "0x00000015" $DIR
	check_mdt_fileset_exist "$fileset" 1 ||
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

	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"
}

test_1() {
	test_1_base "lazy_drop"
	test_1_base "lazy_keep"
	test_1_base "aging_drop"
	test_1_base "aging_keep"
}
run_test 1 "Basic test for WBC with LAZY flush mode"

test_2_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

	setup_wbc "flush_mode=$flush_mode"

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
	oldmd5=$(md5sum $file | awk '{print $1}')
	newmd5=$(md5sum $file2 | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	check_fileset_wbc_flags "$dir $file" "0x00000000"

	rm -rf $dir || error "rm $dir failed"
	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
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
	check_wbc_flags $file "0x00000015"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_wbc_flags $dir "0x00000000"
	check_wbc_flags $file "0x0000000f"
	$MULTIOP $file2 or1c || error "read $file2 failed"
	rm -rf $dir || error "rm $dir failed"

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	echo "QQQQQ" > $file || error "write $file failed"
	check_wbc_flags $file "0x00000015"
	$MULTIOP $file2 or1c || error "read $file2 failed"

	rm -rf $dir || error "rm $dir failed"
}

test_2() {
	test_2_base "lazy_drop"
	test_2_base "lazy_keep"
	test_2_base "aging_drop"
	test_2_base "aging_keep"
}
run_test 2 "Verify remote read works correctly"

test_3_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

	setup_wbc "flush_mode=$flush_mode"

	mkdir $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
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
	check_wbc_flags $file "0x00000015"
	oldmd5=$(md5sum $file | awk '{print $1}')
	$CHECKSTAT -s 1049600 $file || error "$file size wrong"
	$MULTIOP $file2 oc || error "stat $file2 failed"
	check_wbc_flags $DIR/$tdir "0x00000000"
	check_wbc_flags $file "0x0000000f"
	newmd5=$(md5sum $file2 | awk '{print $1}')
	check_wbc_flags $file "0x00000000"
	$CHECKSTAT -s 1049600 $file2 || error "$file size wrong"
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"

	rm -rf $dir || error "rm $dir failed"
}

test_3() {
	test_3_base "lazy_drop"
	test_3_base "lazy_keep"
	test_3_base "aging_drop"
	test_3_base "aging_keep"
}
run_test 3 "Remote read for WBC cached regular file with holes"

test_4_base() {
	local flush_mode=$1
	local dir11="$DIR/$tdir"
	local dir21="$DIR2/$tdir"
	local file11="$dir11/$tfile"
	local file21="$dir21/$tfile"
	local dir12="$dir11/dir2"
	local dir22="$dir21/dir2"
	local file12="$dir12/file2"
	local file22="$dir22/file2"

	setup_wbc "flush_mode=$flush_mode"

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
	check_fileset_wbc_flags "$file11 $dir12 $file12" "0x00000015"
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

	rm -rf $dir11 || error "rm $dir11 failed"
}

test_4() {
	test_4_base "lazy_drop"
	test_4_base "lazy_keep"
	test_4_base "aging_drop"
	test_4_base "aging_keep"
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

test_6_base() {
	local flush_mode=$1
	local file1="$tdir/file1"
	local dir1="$tdir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local flags="0x00000000"
	local interval
	local oldmd5
	local newmd5

	reset_kernel_writeback_param
	interval=$(sysctl -n vm.dirty_expire_centisecs)
	echo "dirty_writeback_centisecs: $interval"

	setup_wbc "flush_mode=$flush_mode"
	wbc_conf_show | grep "flush_mode: aging_keep" &&
		flags="0x00000017"
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
	check_fileset_wbc_flags "$fileset" "0x00000015" $DIR
	sleep $((interval / 100))

	wait_wbc_sync_state $DIR/$file3
	$LFS wbc state $DIR/$tdir $DIR/$file1 $DIR/$dir1 $DIR/$file2 \
		$DIR/$dir2 $DIR/$file3
	check_fileset_wbc_flags "$fileset" "$flags" $DIR
	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist on MDT"

	log "remount client $MOUNT"
	remount_client $MOUNT || error "failed to remount client $MOUNT"
	newmd5=$(md5sum $DIR/$file2 | awk '{print $1}')
	[ "$newmd5" == "$oldmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"

	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"
}

test_6() {
	test_6_base "aging_drop"
	test_6_base "aging_keep"
}
run_test 6 "Verify aging flush mode"

test_7_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local dir1="$dir/dir1"
	local file1="$dir/file1"
	local fileset="$dir1 $file1"
	local expected="400"
	local accd
	local accf

	setup_wbc "flush_mode=$flush_mode"

	mkdir $dir || error "mkdir $dir failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x00000015"
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	chmod $expected $dir1 || error "chmod $expected $dir1 failed"
	chmod $expected $file1 || error "chmod $expected $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	rm -rf $dir || error "rm $dir failed"

	mkdir $dir || error "mkdir $dir failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	check_fileset_wbc_flags "$fileset" "0x00000015"
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

	rm -rf $dir || error "rm $dir failed"
}

test_7() {
	test_7_base "lazy_drop"
	test_7_base "lazy_keep"
	test_7_base "aging_drop"
	test_7_base "aging_keep"
}
run_test 7 "setattr() on the root WBC file"

test_8_base() {
	local flush_mode=$1
	local fileset="$DIR/$tdir/$tfile $DIR/$tdir/l-exist"

	setup_wbc "flush_mode=$flush_mode"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	touch $DIR/$tdir/$tfile || error "touch $DIR/$tdir/$tfile failed"
	ln -s $DIR/$tdir/$tfile $DIR/$tdir/l-exist
	check_fileset_wbc_flags "$fileset" "0x00000015"
	ls -l $DIR/$tdir
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	check_fileset_wbc_flags "$fileset" "0x0000000f"
	$CHECKSTAT -l $DIR/$tdir/$tfile $DIR/$tdir/l-exist ||
		error "$tdir/l-exist not a symlink"
	$CHECKSTAT -f -t f $DIR/$tdir/l-exist ||
		error "$tdir/l-exist not referencing a file"
	ls -l $DIR2/$tdir
	check_fileset_wbc_flags "$fileset" "0x00000000"
	$LFS wbc state $fileset
	$CHECKSTAT -l $DIR/$tdir/$tfile $DIR/$tdir/l-exist ||
		error "$tdir/l-exist not a symlink"
	$CHECKSTAT -f -t f $DIR/$tdir/l-exist ||
		error "$tdir/l-exist not referencing a file"
	rm -f $DIR/$tdir/l-exist
	$CHECKSTAT -a $DIR/$tdir/l-exist || error "$tdir/l-exist not removed"

	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"
}

test_8() {
	test_8_base "lazy_drop"
	test_8_base "lazy_keep"
	test_8_base "aging_drop"
	test_8_base "aging_keep"
}
run_test 8 "Verify symlink works correctly"

test_9() {
	local file="$tdir/$tfile"
	local interval=$(sysctl -n vm.dirty_writeback_centisecs)
	local expire=$(sysctl -n vm.dirty_expire_centisecs)

	echo "dirty_writeback_centisecs: $interval"
	interval=$((interval + 100))
	stack_trap "sysctl -w vm.dirty_expire_centisecs=$expire" EXIT
	sysctl -w vm.dirty_expire_centisecs=$interval

	setup_wbc "flush_mode=aging_keep rmpol=sync"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_wbc_flags $DIR/$tdir "0x0000000f"
	echo "QQQQQ" > $DIR/$file || error "write $DIR/$tfile failed"
	check_wbc_flags $DIR/$file "0x00000015"
	sleep $((interval / 100))
	wait_wbc_sync_state $DIR/$file
	$LFS wbc state $DIR/$file
	check_wbc_flags $DIR/$file "0x00000017"
	unlink $DIR/$file || error "unlink $DIR/$file failed"
	check_mdt_fileset_exist "$file" 1 ||
		error "'$file' should not exist under ROOT on MDT"
}
run_test 9 "Sync remove in aging keep flush mode"

test_10() {
	local file="$DIR/$tdir/$tfile"
	local interval=$(sysctl -n vm.dirty_writeback_centisecs)
	local expire=$(sysctl -n vm.dirty_expire_centisecs)
	local expected="400"
	local accf

	echo "dirty_writeback_centisecs: $interval"
	interval=$((interval + 100))
	stack_trap "sysctl -w vm.dirty_expire_centisecs=$expire" EXIT
	sysctl -w vm.dirty_expire_centisecs=$interval

	setup_wbc "flush_mode=aging_keep rmpol=sync"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "QQQQQ" > $file || error "write $file failed"
	accf=$(stat -c %a $file)
	echo "$file access rights: $accf"
	sleep $((interval / 100))
	wait_wbc_sync_state $file
	check_wbc_flags $file "0x00000017"
	chmod $expected $file || error "chmod $file failed"
	stat $file || error "stat $file failed"
	check_wbc_flags $file "0x00000017"
	accf=$(stat -c %a $file)
	[ $accf == $expected ] ||
		error "$file access rights: $accf, expect $expected"
	stat $DIR2/$tdir/$tfile || error "stat $DIR2/$tdir/$tfile failed"
	accf=$(stat -c %a $DIR2/$tdir/$tfile)
	[ $accf == $expected ] ||
		error "$file access rights: $accf, expect $expected"
}
run_test 10 "setattr in aging keep flush mode"

test_11() {
	local file="$DIR/$tdir/$tfile"
	local interval=$(sysctl -n vm.dirty_writeback_centisecs)
	local expire=$(sysctl -n vm.dirty_expire_centisecs)
	local expected="400"
	local newmd5
	local oldmd5

	echo "dirty_writeback_centisecs: $interval"
	interval=$((interval + 100))
	stack_trap "sysctl -w vm.dirty_expire_centisecs=$expire" EXIT
	sysctl -w vm.dirty_expire_centisecs=$interval

	setup_wbc "flush_mode=aging_drop"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_wbc_flags $DIR/$tdir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
	oldmd5=$(md5sum $file | awk '{print $1}')
	remount_client $MOUNT || error "remount_client $MOUNT failed"
	newmd5=$(md5sum $file | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"

	setup_wbc "flush_mode=aging_keep rmpol=sync"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_wbc_flags $DIR/$tdir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
	oldmd5=$(md5sum $file | awk '{print $1}')
	remount_client $MOUNT || error "remount_client $MOUNT failed"
	newmd5=$(md5sum $file | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_wbc_flags $DIR/$tdir "0x0000000f"
	dd if=/dev/zero of=$file seek=1k bs=1k count=1 ||
		error "failed to write $file"
	check_wbc_flags $file "0x00000015"
	oldmd5=$(md5sum $file | awk '{print $1}')
	wait_wbc_sync_state $file
	check_wbc_flags $file "0x00000017"
	remount_client $MOUNT || error "remount_client $MOUNT failed"
	newmd5=$(md5sum $file | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
}
run_test 11 "Verify umount works correctly"

test_12_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local fileset="$dir $file1 $dir1 $file2 $dir2"

	setup_wbc "flush_mode=$flush_mode"

	mkdir $dir || error "mkdir $dir failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "LLLLL" > $file2 || error "write $file2 failed"
	mkdir $dir2 || error "mkdir $dir2 failed"

	$LFS wbc state $fileset
	sync
	$LFS wbc state $fileset
	check_fileset_wbc_flushed "$fileset"

	ls -R $dir
	unlink $file2 || error "unlink $file2 failed"
	rmdir $dir2 || error "rmdir $dir2 failed"
	rmdir $dir1 || error "rmdir $dir1 failed"
	unlink $file1 || error "unlink $file1 failed"
	ls -R $dir
	rmdir $dir || error "rmdir $dir failed"
}

test_12() {
	test_12_base "lazy_drop"
	test_12_base "lazy_keep"
	test_12_base "aging_drop"
	test_12_base "aging_keep"
}
run_test 12 "Verify sync(2) works correctly"

test_13_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local dir3="$dir2/dir3"
	local file4="$dir3/file4"
	local fileset="$dir $file1 $dir1 $file2 $dir2 $file3 $dir3 $file4"

	setup_wbc "flush_mode=$flush_mode"

	echo -e "\n===== Test fsync(2) on a regular file ====="
	mkdir $dir || error "mkdir $dir failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file2 || error "write $file2 failed"
	mkdir $dir2 || error "mkdir $dir2 failed"
	echo "QQQQQ" > $file3 || error "write $file3 failed"
	mkdir $dir3 || error "mkdir $dir3 failed"
	echo "QQQQQ" > $file4 || error "write $file4 failed"
	$LFS wbc state $fileset
	$MULTIOP $file4 oyc || error "$MULTIOP $file2 oyc failed"
	$LFS wbc state $fileset
	fileset="$dir $dir1 $dir2 $dir3 $file4"
	check_fileset_wbc_flushed "$fileset"

	echo -e "\n===== Test fsync(2) on a directory ====="
	rm -rf $dir || error "rm $dir failed"
	mkdir $dir || error "mkdir $dir failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	mkdir $dir1 || error "mkdir $dir1 failed"
	echo "QQQQQ" > $file2 || error "write $file2 failed"
	mkdir $dir2 || error "mkdir $dir2 failed"
	echo "QQQQQ" > $file3 || error "write $file3 failed"
	mkdir $dir3 || error "mkdir $dir3 failed"
	fileset="$dir $dir1 $dir2 $dir3"
	$LFS wbc state $fileset
	$MULTIOP $dir3 oyc || error "$MULTIOP $dir Dyc failed"
	$LFS wbc state $fileset
	check_fileset_wbc_flushed "$fileset"
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_13() {
	test_13_base "lazy_drop"
	test_13_base "lazy_keep"
	test_13_base "aging_drop"
	test_13_base "aging_keep"
}
run_test 13 "Verify fsync(2) works correctly for four flush modes"

test_14_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local dir3="$dir2/dir3"
	local file4="$dir3/file4"
	local fileset="$dir $file1 $dir1 $file2 $dir2 $file3 $dir3 $file4"

	setup_wbc "flush_mode=$flush_mode"

	mkdir -p $dir3 || error "mkdir -p $dir3 failed"
	echo "QQQQQ" > $file1 || error "write $file1 failed"
	echo "QQQQQ" > $file2 || error "write $file2 failed"
	echo "QQQQQ" > $file3 || error "write $file3 failed"
	echo "QQQQQ" > $file4 || error "write $file4 failed"
	echo "===== WBC state before cache clear ====="
	$LFS wbc state $fileset
	clear_wbc
	echo -e "\n===== WBC state after cache clear ====="
	$LFS wbc state $fileset
	check_fileset_wbc_flags "$fileset" "0x00000000"
	rm -rf $dir || error "rm -rf $dir failed"
}

test_14() {
	test_14_base "lazy_drop"
	test_14_base "lazy_keep"
	test_14_base "aging_drop"
	test_14_base "aging_keep"
}
run_test 14 "Verify the command 'lctl wbc clear' cleans all cached files"

test_15a_base() {
	local flush_mode=$1
	local nr_inodes=$2
	local dir="$DIR/$tdir"
	local prefix="wbcent"
	local fileset

	echo -e "\n===== Inode limits for $flush_mode flush mode ====="
	setup_wbc "flush_mode=$flush_mode max_inodes=$nr_inodes"

	for i in $(seq 1 $nr_inodes); do
		fileset+="$dir/$prefix.i$i "
	done

	echo -e "\n===== Test for regular files ======"
	mkdir $dir || error "mkdir $dir failed"
	touch $fileset || error "touch $fileset failed"
	wbc_conf_show | grep 'inodes_free:'
	$LFS wbc state $fileset
	check_fileset_wbc_flags "$fileset" "0x00000015"
	check_fileset_inode_reserved "$fileset" 1
	touch $dir/$prefix.i0 || error "touch $dir/$prefix.i0 failed"
	wbc_conf_show | grep 'inodes_free:'
	ls $dir
	$LFS wbc state $dir $dir/$prefix.i0 $fileset
	if flush_mode_lock_drop; then
		check_fileset_wbc_flags "$dir $dir/$prefix.i0" "0x00000000"
		check_fileset_wbc_flags "$fileset" "0x0000000f"
	else
		# Protected(P):0x01 | Sync(S):0x02 | Root(R):0x08
		check_wbc_flags $dir "0x0000000b"
		# Protected(P):0x01 | Sync(S):0x02 | Complete(C):0x04
		# Reserved(E): 0x10
		check_fileset_wbc_flags "$fileset" "0x00000007"
		# Protected(P):0x01 | Sync(S):0x02
		check_wbc_flags $dir/$prefix.i0 "0x00000003"
	fi
	check_wbc_inode_reserved $dir/$prefix.i0 0
	wbc_conf_show | grep 'inodes_free:'
	rm -rf $dir || error "rm -rf $dir failed"
	wbc_conf_show | grep 'inodes_free:'

	echo -e "\n===== Test for directories ======"
	mkdir $dir || error "mkdir $dir failed"
	wbc_conf_show | grep 'inodes_free:'
	mkdir $fileset || error "mkdir $fileset failed"
	wbc_conf_show | grep 'inodes_free:'
	$LFS wbc state $fileset
	check_fileset_wbc_flags "$fileset" "0x00000015"
	check_fileset_inode_reserved "$fileset" 1
	mkdir $dir/$prefix.i0 || error "mkdir $dir/$prefix.i0 failed"
	wbc_conf_show | grep 'inodes_free:'
	ls $dir
	$LFS wbc state $dir $dir/$prefix.i0 $fileset
	check_wbc_inode_reserved $dir/$prefix.i0 0
	if flush_mode_lock_drop; then
		check_wbc_flags $dir "0x00000000"
		check_fileset_wbc_flags "$fileset $dir/$prefix.i0" "0x0000000f"
	else
		# Protected(P):0x01 | Sync(S):0x02 | Root(R):0x08
		check_wbc_flags $dir "0x0000000b"
		# Protected(P):0x01 | Sync(S):0x02 | Complete(C):0x04
		# Reserved(E):0x10
		check_fileset_wbc_flags "$fileset" "0x00000007"
		# Protected(P):0x01 | Sync(S):0x02
		check_wbc_flags $dir/$prefix.i0 "0x00000003"
	fi
	wbc_conf_show | grep 'inodes_free:'
	rm -rf $dir || error "rm -rf $dir failed"
}

test_15a() {
	local nr_inodes=10

	test_15a_base "lazy_drop" $nr_inodes
	test_15a_base "lazy_keep" $nr_inodes
	test_15a_base "aging_drop" $nr_inodes
	test_15a_base "aging_keep" $nr_inodes
}
run_test 15a "Inode limits for various flush modes"

test_15b_base() {
	local flush_mode=$1
	local nr_inodes=$2
	local dir="$DIR/$tdir"
	local prefix="wbcent"
	local fileset

	echo -e "\n===== Inode limits for $flush_mode flush mode ====="
	setup_wbc "flush_mode=$flush_mode max_inodes=$nr_inodes"

	echo "Free inodes: $(get_free_inodes) before create regular files"
	for i in $(seq 1 $nr_inodes); do
		fileset+="$dir/$prefix.i$i "
	done

	mkdir $dir || error "mkdir $dir failed"
	$LFS wbc state $dir
	touch $fileset || error "touch $fileset failed"
	echo "Free inodes: $(get_free_inodes) create $nr_inodes files"
	$LFS wbc state $fileset
	check_fileset_wbc_flags "$fileset" "0x00000015"

	touch $dir/$prefix.i0 || error "touch $dir/$prefix.i0 failed"
	echo "Free inodes: $(get_free_inodes) create $((nr_inodes + 1)) files"
	$LFS wbc state $dir $fileset $dir/$prefix.i0
	#check_fileset_inode_reserved "$fileset" 1
	#check_fileset_wbc_flags "$dir $dir/$prefix.i0" "0x00000000"
	#check_fileset_wbc_flags "$fileset" "0x0000000f"
	rm -rf $dir || error "rmdir -rf $dir failed"
}

test_15b() {
	local nr_inodes=1

	test_15b_base "lazy_keep" $nr_inodes
	test_15b_base "aging_keep" $nr_inodes
}
run_test 15b "Inode limits for various lock keep flush modes"

test_15c_base() {
	local flush_mode=$1
	local level=$2
	local nr_level=$3
	local nr_inodes=$(( nr_level * level ))
	local path="$DIR/$tdir"
	local flushset
	local fileset
	local regset
	local file


	echo "level: $level files_per_level: $nr_level max_inodes: $nr_inodes"
	setup_wbc "flush_mode=$flush_mode max_inodes=$nr_inodes"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "Free inodes: $(get_free_inodes) Create: 0"
	for l in $(seq 1 $level); do
		for i in $(seq 1 $nr_level); do
			fileset+="$path/dir_l$l.i$i "
		done
		path+="/dir_l$l.i1"
		flushset+="$path "
	done

	mkdir $fileset || error "mkdir $fileset failed"
	echo "Free inodes: $(get_free_inodes) Create: $nr_inodes"
	$LFS wbc state $DIR/$tdir $fileset
	check_fileset_inode_reserved "$fileset" 1

	file=$path.URSVD.i0
	mkdir $file || error "mkdir $file failed"
	echo "Free inodes: $(get_free_inodes) Create: $(( nr_inodes + 1 ))"
	$LFS wbc state $DIR/$tdir $fileset $file
	check_fileset_inode_reserved "$file" 0
	check_fileset_wbc_flushed "$flushset $file"
	# The parent directory should be decompleted.
	check_wbc_inode_complete $(dirname $file) 0
	rmdir $file || error "rmdir $file failed"
	echo "Free inodes: $(get_free_inodes) rmdir: $file"
	rmdir $path || error "rmdir $path failed"
	echo "Free inodes: $(get_free_inodes) rmdir: $path"
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"

	local free_inodes=$(get_free_inodes)
	[ $free_inodes == $nr_inodes ] ||
		error "free_inodes: $free_inodes != max_inodes: $nr_inodes"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "Free inodes: $(get_free_inodes) Create: 0"
	path="$DIR/$tdir"
	fileset=""
	flushset=""
	for l in $(seq 1 $((level - 1 ))); do
		for i in $(seq 1 $nr_level); do
			fileset+="$path/dir_l$l.i$i "
		done
		path+="/dir_l$l.i1"
		flushset+="$path "
	done

	for i in $(seq 1 $nr_level); do
		regset+="$path/reg_l$level.i$i "
	done

	mkdir $fileset || error "mkdir $fileset failed"
	touch $regset || error "touch $regset failed"
	echo "Free inodes: $(get_free_inodes) Create: $nr_inodes"
	$LFS wbc state $fileset $regset
	check_fileset_inode_reserved "$fileset $regset" 1

	file=$path/reg_l$level.URSVD.i0
	touch $file || error "touch $file failed"
	echo "Free inodes: $(get_free_inodes) Create: $(( nr_inodes + 1 ))"
	$LFS wbc state $fileset $regset $file
	check_fileset_inode_reserved "$file" 0
	check_fileset_wbc_flushed "$flushset $file"
	# The parent directory should be decompleted.
	check_wbc_inode_complete $(dirname $file) 0
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"

	free_inodes=$(get_free_inodes)
	echo "Free inodes: $free_inodes"
	[ $free_inodes == $nr_inodes ] ||
		error "free_inodes: $free_inodes != max_inodes: $nr_inodes"
}

test_15c() {
	stack_trap "cleanup_wbc" EXIT
	echo -e "\n=== Inode limits for lazy keep flush mode ==="
	test_15c_base "lazy_keep" 2 2
	test_15c_base "lazy_keep" 5 6

	echo -e "\n=== Inode limits for aging keep flush mode ==="
	test_15c_base "aging_keep" 5 7
	test_15c_base "aging_keep" 6 8

	echo -e "\n=== Clear WBC caching ==="
	clear_wbc
	echo "Free inodes: $(get_free_inodes)"
	echo -e "\n=== Inode limits for lazy drop flush mode ==="
	test_15c_base "lazy_drop" 3 1
	test_15c_base "lazy_drop" 5 6

	echo -e "\n=== Inode limits for aging drop flush mode ==="
	test_15c_base "aging_drop" 5 7
	test_15c_base "aging_drop" 6 8
}
run_test 15c "Inode limits with multiple level directories"

test_16_base() {
	local flush_mode=$1
	local nr_files=$2
	local blksz=$3
	local count=$4
	local nr_pages=$(( blksz * count / 4096))
	local max_pages=$(( nr_files * nr_pages ))
	local free_pages
	local fileset
	local file

	echo "flush_mode=$1 max_pages=$max_pages nr_files=$2 bs=$3 count=$4"
	setup_wbc "flush_mode=$flush_mode max_pages=$max_pages"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	for i in $(seq 1 $nr_files); do
		file=$DIR/$tdir/$tfile.i$i
		fileset+="$file "
		dd if=/dev/zero of=$file bs=$blksz count=$count conv=notrunc
	done

	echo "Free pages: $(get_free_pages) Write $max_pages pages"
	$LFS wbc state $fileset
	file=$DIR/$tdir/$tfile.i0
	dd if=/dev/zero of=$file bs=$blksz count=$count conv=notrunc
	$LFS wbc state $file $fileset
	echo "Free pages: $(get_free_pages) Write $nr_pages pages more"

	for file in $fileset; do
		echo "write $file"
		dd if=/dev/zero of=$file bs=$blksz count=$(( count + 1 )) \
			conv=notrunc
	done

	$LFS wbc state $fileset
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
	free_pages=$(get_free_pages)
	[ $free_pages == $max_pages ] ||
		error "Free pages is $free_pages, expect $max_pages"
}

test_16() {
	test_16_base "lazy_keep" 1 4096 1
	test_16_base "lazy_keep" 8 4096 16
	test_16_base "aging_keep" 12 4096 32
	test_16_base "aging_keep" 12 1048576 8
}
run_test 16 "page limits for regular files in the lock keep mode"

test_17_base() {
	local flush_mode=$1
	local file1="$DIR/$tdir/$tfile.i1"
	local file2="$DIR/$tdir/$tfile.i2"
	local max_pages=1024
	local free_pages

	setup_wbc "flush_mode=$flush_mode max_pages=$max_pages"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "Write $file1 $file2 bs=4k count=512"
	dd if=/dev/zero of=$file1 bs=4k count=512 || error "Write $file1 failed"
	wbc_conf_show
	dd if=/dev/zero of=$file2 bs=4k count=512 || error "Write $file2 failed"
	$LFS wbc state $file1 $file2
	wbc_conf_show
	free_pages=$(get_free_pages)
	[ $free_pages == 0 ] || error "Free pages got $free_pages, expect 0"

	echo "Write $file1 $file2 bs=4k count=513"
	dd if=/dev/zero of=$file1 bs=4k count=513 || error "Write $file1 failed"
	free_pages=$(get_free_pages)
	[ $free_pages == 512 ] || error "Free pages got $free_pages, expect 512"
	dd if=/dev/zero of=$file2 bs=4k count=513 || error "Write $file2 failed"
	free_pages=$(get_free_pages)
	[ $free_pages == 511 ] || error "Free pages got $free_pages, expect 511"
	$LFS wbc state $file1 $file2

	echo "Write $file1 $file2 bs=4k count=1025"
	dd if=/dev/zero of=$file1 bs=4k count=1025 ||
		error "Write $file1 failed"
	free_pages=$(get_free_pages)
	[ $free_pages == 511 ] || error "Free pages got $free_pages, expect 511"
	dd if=/dev/zero of=$file2 bs=4k count=1025 ||
		error "Write $file2 failed"
	free_pages=$(get_free_pages)
	[ $free_pages == 1024 ] ||
		error "Free pages got $free_pages, expect 1024"
	$LFS wbc state $file1 $file2

	echo "Truncate $file2"
	rm $file2 ||  error "rm $file2 failed"
	dd if=/dev/zero of=$file2 bs=4k count=1024 ||
		error "Write $file2 failed"
	$TRUNCATE $file2 $(( 1048576 * 2 )) || error "Could not truncate $file2"
	free_pages=$(get_free_pages)
	[ $free_pages == 512 ] || error "Free pages got $free_pages, expect 512"
	$TRUNCATE $file2 $(( 1048576 * 2 + 4096 )) ||
		error "Could not truncate $file2"
	free_pages=$(get_free_pages)
	[ $free_pages == 512 ] || error "Free pages got $free_pages, expect 512"
	$TRUNCATE $file2 $(( 1048576 * 2 - 4095 )) ||
		error "Could not truncate $file2"
	free_pages=$(get_free_pages)
	[ $free_pages == 512 ] || error "Free pages got $free_pages, expect 512"
	$TRUNCATE $file2 $(( 1048576 * 2 - 4096 )) ||
		error "Could not truncate $file2"
	free_pages=$(get_free_pages)
	[ $free_pages == 513 ] || error "Free pages got $free_pages, expect 512"
	$TRUNCATE $file2 $(( 1048576 * 2 - 4097 )) ||
		error "Could not truncate $file2"
	free_pages=$(get_free_pages)
	[ $free_pages == 513 ] || error "Free pages got $free_pages, expect 512"

	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_17() {
	test_17_base "lazy_keep"
	test_17_base "aging_keep"
}
run_test 17 "Verify page limits work correctly for truncate in lock keep mode"

test_18_base() {
	local pid1
	local pid2
	local flush_mode=$1
	local file1="$DIR/$tdir/$tfile"
	local file2="$DIR2/$tdir/$tfile"

	echo -e "\n=== reopen test: flush_mode=$flush_mode ==="
	setup_wbc "flush_mode=$flush_mode"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo -n reopen_test_data > $file1 || error "write $file1 failed"
	$LFS wbc state $file1
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	$LFS wbc state $file1
	$MULTIOP $file1 O_c &
	pid1=$!
	stat $file2 || error "stat $file2 failed"
	$LFS wbc state $file1
	kill -USR1 $pid1 && wait $pid1 || error "multiop failure"
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo -n reopen2_test_data > $file1 || error "write $file1 failed"
	$LFS wbc state $file1
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	$LFS wbc state $file1
	$MULTIOP $file1 O_c &
	pid1=$!
	$MULTIOP $file1 O_c &
	pid2=$!
	sleep 2
	stat $file2 || error "stat $file2 failed"
	$LFS wbc state $file1
	kill -USR1 $pid1 && wait $pid1|| error "multiop failure"
	kill -USR1 $pid2 && wait $pid2 || error "multiop failure"
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_18() {
	test_18_base "lazy_drop"
	test_18_base "lazy_keep"
	test_18_base "aging_drop"
	test_18_base "aging_keep"
}
run_test 18 "reopen files when EX WBC lock is revoking for regular files"

test_19() {
	local pid
	local flush_mode="lazy_keep"
	local file1="$DIR/$tdir/$tfile"
	local file2="$DIR2/$tdir/$tfile"

	echo -e "\n=== reopen on remote remove: flush_mode=$flush_mode ==="
	setup_wbc "flush_mode=$flush_mode"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$MULTIOP $file1 Ow40960_c &
	pid=$!
	sleep 2
	ls $DIR/$tdir
	$LFS wbc state $DIR/$tdir $file1
	unlink $file2 || error "unlink $file2 failed"
	kill -USR1 $pid && wait $pid || error "multiop failure"
}
run_test 19 "reopen on remote unlink"

test_20_base() {
	local flush_mode=$1
	local file="$DIR/$tdir/$tfile"
	local file2="$DIR2/$tdir/$tfile"

	echo -e "\n=== reopen upon remote remove: flush_mode=$flush_mode ==="
	setup_wbc "flush_mode=$flush_mode"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	openunlink $file $file2 || error "openunlink $file $file2"
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_20() {
	test_20_base "lazy_drop"
	test_20_base "lazy_keep"
	test_20_base "aging_drop"
	test_20_base "aging_keep"
}
run_test 20 "remove open file on other client node"

test_21_base() {
	local flush_mode=$1
	local readdir_pol=$2
	local num_dirents=$3
	local comp_expect=$4

	echo "=== readdir() flush_mode=$flush_mode num_dirents=$num_dirents ==="
	setup_wbc "flush_mode=$flush_mode readdir_pol=$2"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	for i in $(seq -f "%04g" 1 $num_dirents); do
		touch $DIR/$tdir/$tfile.$i
	done

	# For a 4-6 bytes file name entry, it is occupied 24 bytes to fill
	# linux_dirent64 data structure.
	# In libc, it provides 32K buffer for reading linux_dirent64
	# structures from the directory. It is large enough to hold nearly
	# 1356 dirents.
	local num_ls=$(ls $DIR/$tdir | wc -l)
	local num_uniq=$(ls $DIR/$tdir | sort -u | wc -l)
	local num_all=$(ls -a $DIR/$tdir | wc -l)

	if [ $num_ls -ne $num_dirents ] || [ $num_uniq -ne $num_dirents ] ||
		[ $num_all -ne $((num_dirents + 2)) ]; then
		error "Expected $num_dirents files, got $num_ls " \
		      "($num_uniq unique $num_all .&..)"
	fi

	$LFS wbc state $DIR/$tdir
	check_wbc_inode_complete $DIR/$tdir $comp_expect
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_21() {
	test_21_base "lazy_drop" "dcache_compat" 1500 1
	test_21_base "lazy_keep" "dcache_compat" 1500 1
	test_21_base "aging_drop" "dcache_compat" 1500 1
	test_21_base "aging_keep" "dcache_compat" 1500 1

	test_21_base "lazy_drop" "dcache_decomp" 500 1
	test_21_base "lazy_keep" "dcache_decomp" 500 1
	test_21_base "aging_drop" "dcache_decomp" 500 1
	test_21_base "aging_keep" "dcache_decomp" 500 1

	# The directory is too big to read dir entries in one blow.
	# We must first decomplete the directory and then read from MDT.
	test_21_base "lazy_drop" "dcache_decomp" 1500 0
	test_21_base "lazy_keep" "dcache_decomp" 1500 0
	test_21_base "aging_drop" "dcache_decomp" 1500 0
	test_21_base "aging_keep" "dcache_decomp" 1500 0
}
run_test 21 "Verfiy readdir() works correctly for various readdir policies"

test_22_base() {
	local flush_mode=$1
	local unrsv_flag=$2
	local nr_files=1
	local dir=$DIR/$tdir
	local file=$dir/$tfile.i0
	local fileset

	echo -e "\n===== Unreserve testing for $flush_mode flush mode ====="
	setup_wbc "flush_mode=$flush_mode"

	# One level directory test.
	for i in $(seq 1 $nr_files); do
		fileset+="$dir/$tfile.i$i "
	done

	mkdir $dir || error "mkdir $dir failed"
	$LFS wbc state $dir
	touch $fileset $file || error "touch $fileset $file failed"
	echo "=== Regular file: lfs wbc unreserve $unrsv_flag $file ==="
	$LFS wbc unreserve $unrsv_flag $file || error "unreserve $file failed"
	$LFS wbc state $file $fileset
	check_wbc_inode_complete $dir 0
	check_wbc_inode_reserved $file 0
	[[ -z $unrsv_flag ]] || check_fileset_inode_reserved "$fieset" 0
	rm -rf $dir || error "rm -rf $dir failed"

	fileset=""
	file="$dir/$tdir.i0"
	for i in $(seq 1 $nr_files); do
		fileset+="$dir/$tdir.i$i "
	done

	mkdir $dir || error "mkdir $dir failed"
	$LFS wbc state $dir
	mkdir $fileset $file || error "mkdir $fileset $file failed"
	echo "=== Directory: lfs wbc unreserve $unrsv_flag $file ==="
	$LFS wbc unreserve $unrsv_flag $file || error "unreserve $file failed"
	check_wbc_inode_complete $dir 0
	check_wbc_inode_reserved $file 0
	[[ -z $unrsv_flag ]] || check_fileset_inode_reserved "$fieset" 0
	rm -rf $dir || error "rm -rf $dir failed"
}

test_22() {
	#test_22_base "lazy_drop"
	test_22_base "lazy_keep"
	test_22_base "lazy_drop" "-R"
	test_22_base "lazy_keep" "-R"

	test_22_base "aging_drop"
	test_22_base "aging_keep"
	test_22_base "aging_drop" "-R"
	test_22_base "aging_keep" "-R"
}
run_test 22 "lfs unreserve command with 1 level directory"

test_23_base() {
	local flush_mode=$1
	local level=$2
	local nr_level=$3
	local unrsv_level=$4
	local unrsv_flag=$5
	local path="$DIR/$tdir"
	local fileset
	local unrsvset
	local subset
	local file

	echo -e "\n===== Inode limits for $flush_mode flush mode ====="
	setup_wbc "flush_mode=$flush_mode"

	for l in $(seq 1 $level); do
		subset=""
		for i in $(seq 1 $nr_level); do
			fileset+="$path/dir_l$l.i$i "
			subset+="$path/dir_l$l.i$i "
		done
		if [ $l == $unrsv_level ]; then
			file="$path/dir_l$l.i1"
			unrsvset="$subset"
		fi
		path+="/dir_l$l.i1"
	done

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	mkdir $fileset || error "mkdir $fileset failed"
	$LFS wbc state $DIR/$tdir $fileset
	check_fileset_inode_reserved "$fileset" 1
	echo "=== Directory: lfs wbc unreserve $unrsv_flag $file ==="
	$LFS wbc unreserve $unrsv_flag $file || error "unreserve $file failed"
	$LFS wbc state $DIR/$tdir $fileset
	check_wbc_inode_complete $(dirname $file) 0
	check_wbc_inode_reserved $file 0
	[ -z $unrsv_flag ] || check_fileset_inode_reserved "$unrsvset" 0
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"

	file="$(dirname $file)/dir_l$unrsv_level.i0"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	mkdir $fileset || error "mkdir $fileset failed"
	echo -n unreserve_reg_data > $file || error "write $file failed"
	$LFS wbc state $DIR/$tdir $fileset $file
	check_fileset_inode_reserved "$fileset" 1
	echo "=== Regular file: lfs wbc unreserve $unrsv_flag $file ==="
	$LFS wbc unreserve $unrsv_flag $file || error "unreserve $file failed"
	$LFS wbc state $DIR/$tdir $fileset $file
	check_wbc_inode_complete $(dirname $file) 0
	check_wbc_inode_reserved $file 0
	[[ -z $unrsv_flag ]] || check_fileset_inode_reserved "$unrsvset" 0
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_23() {
	test_23_base "lazy_drop" 3 3 3
	test_23_base "lazy_drop" 3 3 3 "-R"
	test_23_base "lazy_drop" 3 3 2
	test_23_base "lazy_drop" 3 3 2 "-R"
	test_23_base "lazy_drop" 3 3 1
	test_23_base "lazy_drop" 3 3 1 "-R"

	test_23_base "lazy_keep" 3 3 3
	test_23_base "lazy_keep" 3 3 3 "-R"
	test_23_base "lazy_keep" 3 3 2
	test_23_base "lazy_keep" 3 3 2 "-R"
	test_23_base "lazy_keep" 3 3 1
	test_23_base "lazy_keep" 3 3 1 "-R"

	test_23_base "aging_drop" 3 3 3
	test_23_base "aging_drop" 3 3 3 "-R"
	test_23_base "aging_drop" 3 3 2
	test_23_base "aging_drop" 3 3 2 "-R"
	test_23_base "aging_drop" 3 3 1
	test_23_base "aging_drop" 3 3 1 "-R"

	test_23_base "aging_keep" 3 3 3
	test_23_base "aging_keep" 3 3 3 "-R"
	test_23_base "aging_keep" 3 3 2
	test_23_base "aging_keep" 3 3 2 "-R"
	test_23_base "aging_keep" 3 3 1
	test_23_base "aging_keep" 3 3 1 "-R"
}
run_test 23 "lfs unreserve command with multiple level directories"

test_24_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local limit=10000
	local ratio=80
	local hiwm=$(( limit * ratio / 100 ))
	local free_inodes

	echo "=== flush_mode=$flush_mode max_inodes=$limit ratio=$ratio ==="
	setup_wbc "flush_mode=$flush_mode max_inodes=$limit hiwm_ratio=$ratio"

	mkdir $dir || error "mkdir $dir failed"
	createmany -d $dir/d $hiwm || {
		unlinkmany -d $dir/d $hiwm
		error "create $hiwm files in $dir failed"
	}
	$LFS wbc state $dir
	wbc_conf_show
	unlinkmany -d $dir/d $hiwm ||
		error "unlink $hiwm files in $dir failed"

	createmany -d $dir/d $(( hiwm + 100 )) || {
		unlinkmany -d $dir/d $(( hiwm + 100 ))
		error "create $(( hiwm + 100 )) files in $dir failed"
	}
	free_inodes=$(get_free_inodes)
	[ $free_inodes == 10000 ] ||
		error "free inodes: $free_inodes, expect 10000"
	check_wbc_inode_complete $dir 0
	unlinkmany -d $dir/d $hiwm ||
		error "unlink $hiwm files in $dir failed"

	createmany -m $dir/f $hiwm || {
		unlinkmany $dir/f $hiwm
		error "create $hiwm files in $dir failed"
	}
	$LFS wbc state $dir
	wbc_conf_show
	unlinkmany $dir/f $hiwm ||
		error "unlink $hiwm files in $dir failed"

	createmany -m $dir/f $(( hiwm + 100 )) || {
		unlinkmany $dir/f $(( hiwm + 100 ))
		error "create $(( hiwm + 100 )) files in $dir failed"
	}
	free_inodes=$(get_free_inodes)
	[ $free_inodes == 10000 ] ||
		error "free inodes: $free_inodes, expect 10000"
	check_wbc_inode_complete $dir 0
	unlinkmany $dir/f $hiwm ||
		error "unlink $hiwm files in $dir failed"

	rm -rf $dir || error "rm -rf $dir failed"
}

test_24() {
	test_24_base "lazy_drop"
	test_24_base "lazy_keep"
	test_24_base "aging_drop"
	test_24_base "aging_keep"
}
run_test 24 "WBC inodes reclaim mechanism with single level directory"

test_25_base() {
	local flush_mode=$1
	local level=$2
	local nr_level=$3
	local ratio=80
	local limit=$(( level * nr_level ))
	local hiwm=$(( limit * ratio / 100 ))
	local path="$DIR/$tdir"
	local fileset
	local free_inodes
	local used_inodes

	echo "== flush_mode=$flush_mode max_inodes=$limit hiwm_ratio=$ratio  =="
	setup_wbc "flush_mode=$flush_mode max_inodes=$limit hiwm_ratio=$ratio"

	for l in $(seq 1 $level); do
		for i in $(seq 1 $nr_level); do
			fileset+="$path/dir_l$l.i$i "
		done
		path+="/dir_l$l.i1"
	done

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	mkdir $fileset || error "mkdir $fileset failed"
	sleep 5
	wbc_conf_show
	free_inodes=$(get_free_inodes)
	used_inodes=$(( limit - free_inodes ))
	[ $used_inodes -lt $hiwm ] || error "used:$used_inodes > hiwm:$hiwm"
	[ $limit -lt 30 ] && $LFS wbc state $fileset $DIR/$tdir
	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_25() {
	test_25_base "lazy_drop" 10 2
	test_25_base "lazy_drop" 10 1000
	test_25_base "lazy_keep" 10 2
	test_25_base "lazy_keep" 10 1000

	test_25_base "aging_keep" 10 2
	test_25_base "aging_keep" 10 1000
	test_25_base "aging_drop" 10 2
	test_25_base "aging_drop" 10 1000
}
run_test 25 "WBC inodes reclaim mechanism with multiple level directories"

test_26_base() {
	local flush_mode=$1
	local nr_files=$2
	local nr_file_pages=$3
	local ratio=80
	local limit=$(( nr_files * nr_file_pages ))
	local hiwm=$(( limit * ratio / 100 ))
	local dir="$DIR/$tdir"
	local free_pages
	local used_pages

	echo "== flush_mode=$flush_mode max_pages=$limit hiwm_ratio=$ratio  =="
	setup_wbc "flush_mode=$flush_mode max_pages=$limit hiwm_ratio=$ratio"

	mkdir $dir || error "mkdir $dir failed"
	for i in $(seq 1 $nr_files); do
		dd if=/dev/zero of=$dir/$tfile.i$i bs=4k count=$nr_file_pages ||
			error "Write $dir/$tfile.i$i failed"
	done

	sleep 5
	wbc_conf_show
	free_pages=$(get_free_pages)
	used_pages=$(( limit - free_pages ))
	[ $used_pages -le $hiwm ] || error "used: $used_pages > hiwm: $hiwm"

	rm -rf $dir || error "rm -rf $dir failed"
}

test_26() {
	test_26_base "lazy_drop" 10 1024
	test_26_base "lazy_keep" 10 1024
	test_26_base "aging_drop" 10 1024
	test_26_base "aging_keep" 10 1024
}
run_test 26 "WBC pages reclaim mechanism with 1 level direcotry"

test_27() {
	local flush_mode="aging_keep"
	local dir=$DIR/$tdir
	local file=$dir/$tfile

	setup_wbc "flush_mode=$flush_mode"
	mkdir $dir || error "mkdir $dir failed"

	local min_size_ost=$(($($LFS df | awk "/$FSNAME-OST/ { print \$4 }" |
		sort -un | head -1) / 1024))
	local size=$(($(awk '/MemFree:/ { print $2 }' /proc/meminfo) / 1024))

	[[ $size -gt $min_size_ost ]] && size=$min_size_ost
	size=$(((size * 80) / 100))
	echo "I/O size to use for I/O: $size"
	stack_trap "rm -f $file; wait_delete_completed"
	dd if=/dev/zero of=$file bs=1M count=$size ||
		error "write $file with $size MiB failed"
	$LFS wbc state $dir
	$LFS wbc state $file
}
run_test 27 "Write a larger file into WBC shoud not trap into an endless loop"

test_28_base() {
	local flush_mode=$1
	local parent=$tdir
	local nr_level=$2
	local level=$3

	echo "== flush_mode=$flush_mode nr_level=$nr_level level=$level  =="
	setup_wbc "flush_mode=$flush_mode flush_pol=batch"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_wbc_flags $DIR/$tdir "0x0000000f"

	local fileset
	local child
	local dir2

	for l in $(seq 1 $level); do
		for i in $(seq 1 $nr_level); do
			child=$parent/dir_l$l.i$i
			fileset+="$child "
			mkdir $DIR/$child || error "mkdir $DIR/$child failed"
		done
		parent+="/dir_l$l.i1"
	done

	stat $DIR2/$parent || error "stat $DIR2/$parent failed"
	check_mdt_fileset_exist "$fileset" 0 ||
		error "'$fileset' should exist under ROOT on MDT"

	rm -rf $DIR/$tdir || error "rm -rf $DIR/$tdir failed"
}

test_28() {
	test_28_base "lazy_drop" 128 3
	test_28_base "lazy_keep" 128 3
	test_28_base "aging_drop" 128 3
	test_28_base "aging_keep" 128 3
}
run_test 28 "batch flush when root WBC EX lock is revoking"

test_29() {
	local dir=$DIR/$tdir
	local file=$dir/$tfile.1
	local file2=$dir/$tfile.2

	mkdir $dir || error "mkdir $dir failed"
	echo "QQQQQ" > $file || error "echo $file failed"
	mv $file $file2 || error "rename $file $file2 failed"
}
run_test 29 "Verify normal rename() work correctly"

test_100() {
	local dir=$DIR/$tdir
	local file1="$dir/$tfile.1"
	local file2="$dir/$tfile.2"

	sysctl -w vm.dirty_expire_centisecs=500
	setup_wbc "flush_mode=aging_drop"
	mkdir $dir || error "mkdir $dir failed"
	touch $file1 || error "touch $file1 failed"

	#define OBD_FAIL_LLITE_MEMFS_LOOKUP_PAUSE	0x141a
	$LCTL set_param fail_loc=0x8000141a fail_val=10
	touch $file2 || error "touch $file2 failed"

	$LFS wbc state $file1 $file2
}
run_test 100 "MemFS lookup without atomic_open()"

test_101() {
	local dir=$DIR/$tdir
	local file=$dir/$tfile

	sysctl -w vm.dirty_expire_centisecs=500
	sysctl -w vm.dirty_writeback_centisecs=400
	setup_wbc "flush_mode=aging_drop"

	#define OBD_FAIL_LLITE_WBC_FLUSH_PAUSE	0x141b
	$LCTL set_param fail_loc=0x8000141b fail_val=20
	mkdir $dir || error "mkdir $dir failed"
	echo "SYNC_NONE" > $file || error "write $file failed"
	$LFS wbc state $dir $file
	$MULTIOP $file oyc
}
run_test 101 "Racer between two flusher thread with WB_SYNC_NONE mode"

test_102() {
	local flush_mode="aging_keep"
	local dir="$DIR/$tdir"
	local dir_l1="$dir/${tdir}_l1"
	local max_inodes=5
	local fileset=""

	setup_wbc "flush_mode=aging_keep max_inodes=$max_inodes"

	mkdir $dir || error "mkdir $dir failed"
	mkdir $dir_l1 || error "mkdir $dir_l1 failed"
	for i in $(seq 1 $max_inodes); do
		fileset+="$dir_l1/${tdir}_l2.i$i "
	done

	mkdir $fileset || error "mkdir $fileset failed"
	$LFS wbc state $dir $dir_l1 $fileset
	echo "QQQQQQ" > $dir_l1/${tfile}_l2.i1
	touch $dir_l1/${tdir}_l2.i1/file1
	echo "QQQQQ" > $dir_l1/${tdir}_l2.i1/file2

	echo -e "\nFinish =============== "
	$LFS wbc state $dir_l1/${tfile}_l2.i1 $dir_l1/${tdir}_l2.i1/file1 \
		$dir_l1/${tdir}_l2.i1/file2
}
run_test 102 "create files under a decompleted directory"

test_103_base() {
	local flush_mode=$1
	local dir="$DIR/$tdir"
	local nr_level=$2
	local level=$3

	[ $MDSCOUNT -lt 2 ] && skip_env "needs >= 2 MDTs"

	echo "== flush_mode=$flush_mode nr_level=$nr_level level=$level  =="
	setup_wbc "flush_mode=$flush_mode"

	$LFS mkdir -c $MDSCOUNT -H crush $dir || error "mkdir $dir failed"
	check_wbc_flags $dir "0x00000000"
	echo "$dir LMV info:"
	$LFS getdirstripe $DIR/$tdir

	local idx
	local cidx
	local parent
	local child

	for i in $(seq 1 $nr_level); do
		parent="$dir/wbcroot.i$i"
		mkdir $parent || error "mkdir $parent failed"
		check_wbc_flags $parent "0x0000000f"
		idx=$($LFS getstripe -m $parent)
		echo -e "\nParent $parent mdt_index: $idx"
		for l in $(seq 1 $level); do
			for n in $(seq 1 $nr_level); do
				child=$parent/dir_l$l.i$n
				mkdir $child || error "mkdir $child failed"
				cidx=$($LFS getstripe -m $child)
				echo "Child $child mdt_index: $cidx"
				[ $idx == $cidx ] || error "diff mdx idx"
			done
			parent+="/dir_l$l.i1"
		done
	done

	rm -rf $dir || error "rm -rf $dir failed"
}

test_103() {
	test_103_base "lazy_drop" 4 3
	test_103_base "lazy_keep" 4 3
	test_103_base "aging_drop" 4 3
	test_103_base "aging_keep" 4 3
}
run_test 103 "DNE: Fids allocated on the target same with root WBC directory"

test_104() {
	local flush_mode="aging_keep"
	local max=32
	local nr=64

	setup_wbc "flush_mode=$flush_mode flush_pol=batch max_batch_count=$max"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	local fileset
	local mds_index

	mds_index=$(($($LFS getstripe -m $DIR/$tdir) + 1))
	for i in $(seq 1 $nr); do
		fileset+="$DIR/$tdir/$tfile.$i "
	done

	touch $fileset || error "touch $fileset failed"
	ls $DIR/$tdir
	drop_batch_reply $mds_index "stat $DIR2/$tdir" || error "stat failed"
}
run_test 104 "drop batch reply during flush caused by the lock revocation"

test_105a() {
	local flush_mode="lazy_keep"

	setup_wbc "flush_mode=$flush_mode"
	replay_barrier $SINGLEMDS
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	fail $SINGLEMDS
}
run_test 105a "Replay recovery for root WBC dir"

test_105b() {
	local flush_mode="aging_keep"
	local mds_index

	setup_wbc "flush_mode=$flush_mode"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	touch $DIR/$tdir/$tfile || error "touch $DIR/$tdir/$tfile failed"
	mds_index=$(($($LFS getstripe -m $DIR/$tdir) + 1))
	replay_barrier_nosync mds$mds_index
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	$LFS wbc state $DIR/$tdir/$tfile
	check_wbc_flags $DIR/$tdir/$tfile "0x0000000f"
	fail mds$mds_index
	$LFS wbc state $DIR/$tdir/$tfile
	check_wbc_flags $DIR/$tdir/$file "0x00000000"
	check_mdt_fileset_exist "$tdir/$tfile" 0 ||
		error "'$tdir/$tfile' should exist on MDT"
}
run_test 105b "Replay recovery for WBC"

test_105c() {
	local flush_mode="aging_keep"
	local mds_index

	lctl set_param -n ldlm.cancel_unused_locks_before_replay "0"
	setup_wbc "flush_mode=$flush_mode"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	touch $DIR/$tdir/$tfile || error "touch $DIR/$tdir/$tfile failed"
	mds_index=$(($($LFS getstripe -m $DIR/$tdir) + 1))
	replay_barrier_nosync mds$mds_index
	stat $DIR2/$tdir || error "stat $DIR2/$tdir failed"
	$LFS wbc state $DIR/$tdir/$tfile
	check_wbc_flags $DIR/$tdir/$tfile "0x0000000f"
	fail mds$mds_index
	$LFS wbc state $DIR/$tdir/$tfile
	check_wbc_flags $DIR/$tdir/$tfile "0x0000000f"
	check_mdt_fileset_exist "$tdir/$tfile" 0 ||
		error "'$tdir/$tfile' should exist on MDT"

	stat $DIR2/$tdir/$tfile || error "stat $DIR2/$tdir/$tfile failed"
	$LFS wbc state $DIR/$tdir/$tfile
	check_wbc_flags $DIR/$tdir/$tfile "0x00000000"
	lctl set_param -n ldlm.cancel_unused_locks_before_replay "1"
}
run_test 105c "Replay recovery for WBC without canceling unused locks"

test_sanity() {
	local cmd="$LCTL set_param llite.*.wbc.conf=enable"

	ONLY="17a 17b 17c 17d 17e 17f 25a 25b 26a 26b 26c 26d 26e 26f 32e 32f \
		32g 32h 32m 32n 32o 32p" WBC="yes" CONF="$cmd" bash sanity.sh

	return 0
}
#run_test sanity "Run sanity with WBC files"

log "cleanup: ======================================================"

# kill and wait in each test only guarentee script finish, but command in script
# like 'rm' 'chmod' may still be running, wait for all commands to finish
# otherwise umount below will fail
[ "$(mount | grep $MOUNT2)" ] && wait_update $HOSTNAME "fuser -m $MOUNT2" "" ||
	true

complete $SECONDS
check_and_cleanup_lustre
exit_status
