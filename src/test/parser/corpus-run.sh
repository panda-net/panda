#! /bin/sh
#
# Script to run test_parser on a test corpus of pcap files.
#
# Usage: $0 pcap-dir corename output-dir
#
# The first argument is a directory to find the pcap files in.  The
#  script will treat each file with a name ending in .pcap in this
#  directory as an input file.
#
# The second argument is the name of the dissector core to use; see the
#  documentation for test_parser's -c option.
#
# The third argument is a directory to put the output in.  This
#  directory must already exist; for each input file, one or two output
#  files are created here.  One is always created; its name is the
#  input file name relative to the pcap-dir, with .out appended.  This
#  contains stdout from the run.  The other one is always created, but,
#  if it's empty after the run, is deleted; this one is named with .err
#  appended and contains stderr from the run.
#
# Note that this script does not remove anything from output-dir before
#  starting; if it has things in it, they will get overwritten and
#  possibly removed after that (if their names collide with the names
#  outlined above) or be left untouched (if not).
#
# If any of the files in pcap-dir have newlines in their names, this
#  script will misfire; other shell metacharacters in filenames may
#  cause trouble, though I have tried to insulate the script against
#  such trouble to the extent that it's easy to do so.
#
# There are numerous sources of pcap test files on the net.  Two of the
#  better ones are the ones used by tcpdump and wireshark. There may
#  be others.
#
# The tcpdump test corpus is a github repo:
#  https://github.com/the-tcpdump-group/tcpdump/tree/master/tests
#  git://github.com/the-tcpdump-group/tcpdump/tree/master/tests
#  probably will also work to clone the repo.
#
# The wireshark ones are at:
#  https://www.wireshark.org/download/automated/captures/
#  is a (largeish, a bit over a megabyte) page listing the various files
#  with links to the data files;
#
# Note that the wireshark corpus is *substantially* larger than the
#  tcpdump one.  According to du -s, the tcpdump corpus on my dev
#  machine is 24200K, the wireshark one 13732132K - very loosely put,
#  24 megs for tcpdump versus 13 gigs for wireshark.
#

case $# in
	3)	;;
	*)	echo "Usage: $0 pcap-dir core output-dir" 1>&2
		exit 1
		;;
esac

idir="$1"
core="$2"
odir="$3"

case "$idir" in
	/*)	;;
	./*)	;;
	*)	idir=./"$idir" ;;
esac

case "$odir" in
	/*)	;;
	./*)	;;
	*)	odir=./"$odir" ;;
esac

if ! [ -d "$idir" -a -d "$odir" ]; then
	echo "$0: directories named must already exist." 1>&2
	exit 1
fi

case `./test_parser -c "$core" 2>&1` in
	*"unknown core"*)
		echo "$0: unsupported core name $core" 1>&2
		exit 1
		;;
esac

ls "$idir" |
  egrep "[.]pcap$" |
  while read f
  do
	./test_parser -i pcap,"$idir/$f" -c "$core" -o text > "$odir/$f.out" 2> "$odir/$f.err"
	if [ ! -s "$odir/$f.err" ]; then
		rm "$odir/$f.err"
	fi
  done
