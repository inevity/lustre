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

test_1_base() {
	local file1="$tdir/file1"
	local dir1="$tdir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$tdir/file3"
	local file4="$tdir/file4"
	local file5="$tdir/file5"
	local file6="$tdir/file6"

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

	rm -rf $DIR/$tdir || error "rm $DIR/$tdir failed"
}

test_1() {
	setup_wbc
	test_1_base

	setup_wbc "flush_mode=aging_drop"
	test_1_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_1_base
}
run_test 1 "Basic test for WBC with LAZY flush mode"

test_2_base() {
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

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
	setup_wbc
	test_2_base

	setup_wbc "flush_mode=aging_drop"
	test_2_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_2_base
}
run_test 2 "Verify remote read works correctly"

test_3_base() {
	local dir="$DIR/$tdir"
	local file="$dir/$tfile"
	local file2="$DIR2/$tdir/$tfile"
	local oldmd5
	local newmd5

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
	setup_wbc
	test_3_base

	setup_wbc "flush_mode=aging_drop"
	test_3_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_3_base
}
run_test 3 "Remote read for WBC cached regular file with holes"

test_4_base() {
	local dir11="$DIR/$tdir"
	local dir21="$DIR2/$tdir"
	local file11="$dir11/$tfile"
	local file21="$dir21/$tfile"
	local dir12="$dir11/dir2"
	local dir22="$dir21/dir2"
	local file12="$dir12/file2"
	local file22="$dir22/file2"

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
	setup_wbc
	test_4_base

	setup_wbc "flush_mode=aging_drop"
	test_4_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_4_base
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
	setup_wbc "flush_mode=aging_drop"
	test_6_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_6_base
}
run_test 6 "Verify aging flush mode"

test_7_base() {
	local dir="$DIR/$tdir"
	local dir1="$dir/dir1"
	local file1="$dir/file1"
	local fileset="$dir1 $file1"
	local expected="400"
	local accd
	local accf

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
	setup_wbc
	test_7_base

	setup_wbc "flush_mode=aging_drop"
	test_7_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_7_base
}
run_test 7 "setattr() on the root WBC file"

test_8_base() {
	local fileset="$DIR/$tdir/$tfile $DIR/$tdir/l-exist"

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
	setup_wbc
	test_8_base

	setup_wbc "flush_mode=aging_drop"
	test_8_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_8_base
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
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local fileset="$dir $file1 $dir1 $file2 $dir2"

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
	setup_wbc "flush_mode=lazy_drop"
	test_12_base

	setup_wbc "flush_mode=aging_drop rmpol=sync"
	test_12_base

	setup_wbc "flush_mode=lazy_keep rmpol=sync"
	test_12_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_12_base
}
run_test 12 "Verify sync(2) works correctly"

test_13() {
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local dir3="$dir2/dir3"
	local file4="$dir3/file4"
	local fileset="$dir $file1 $dir1 $file2 $dir2 $file3 $dir3 $file4"

	setup_wbc "flush_mode=aging_keep rmpol=sync"

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
}
run_test 13 "Verify fsync(2) works correctly for aging keep flush mode"

test_14_base() {
	local dir="$DIR/$tdir"
	local file1="$dir/file1"
	local dir1="$dir/dir1"
	local file2="$dir1/file2"
	local dir2="$dir1/dir2"
	local file3="$dir2/file3"
	local dir3="$dir2/dir3"
	local file4="$dir3/file4"
	local fileset="$dir $file1 $dir1 $file2 $dir2 $file3 $dir3 $file4"

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
	setup_wbc
	test_14_base

	setup_wbc "flush_mode=aging_drop"
	test_14_base

	setup_wbc "flush_mode=aging_keep rmpol=sync"
	test_14_base
}
run_test 14 "Verify the command 'lctl wbc clear' cleans all cached files"

test_15a_base() {
	local dir="$DIR/$tdir"
	local nr_inodes=$1
	local prefix="wbcent"
	local fileset

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
		# Protected(P):0x01 | Sync(S):0x02 | Complete(C):0x04 |
		# Reserved(E): 0x10
		check_fileset_wbc_flags "$fileset" "0x00000017"
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
		# Protected(P):0x01 | Sync(S):0x02 | Complete(C):0x04 |
		# Reserved(E):0x10
		check_fileset_wbc_flags "$fileset" "0x00000017"
		# Protected(P):0x01 | Sync(S):0x02
		check_wbc_flags $dir/$prefix.i0 "0x00000003"
	fi
	wbc_conf_show | grep 'inodes_free:'
	rm -rf $dir || error "rm -rf $dir failed"
}

test_15a() {
	local nr_inodes=10

	echo "===== Inode limits for lazy drop flush mode ====="
	setup_wbc "flush_mode=lazy_drop max_inodes=$nr_inodes"
	test_15a_base $nr_inodes

	echo -e "\n===== Inode limits for aging drop flush mode ====="
	setup_wbc "flush_mode=aging_drop max_inodes=$nr_inodes"
	test_15a_base $nr_inodes

	echo -e "\n===== Inode limits for lazy keep flush mode ====="
	setup_wbc "flush_mode=lazy_keep max_inodes=$nr_inodes"
	test_15a_base $nr_inodes

	echo -e "\n===== Inode limits for aging keep flush mode ====="
	setup_wbc "flush_mode=aging_keep max_inodes=$nr_inodes"
	test_15a_base $nr_inodes
}
run_test 15a "Inode limits for various flush modes"

test_15b_base() {
	local dir="$DIR/$tdir"
	local nr_inodes=$1
	local prefix="wbcent"
	local fileset

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
	local nr_inodes=10

	echo -e "\n===== Inode limits for lazy keep flush mode ====="
	setup_wbc "flush_mode=lazy_keep max_inodes=$nr_inodes"
	test_15b_base $nr_inodes

	echo -e "\n===== Inode limits for aging keep flush mode ====="
	setup_wbc "flush_mode=aging_keep max_inodes=$nr_inodes"
	test_15b_base $nr_inodes
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
	test_15c_base "lazy_keep" 2 3
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
run_test 15c "Inode limits for lock keep modes with multiple level directories"

test_sanity() {
	local cmd="$LCTL wbc enable $MOUNT"

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
