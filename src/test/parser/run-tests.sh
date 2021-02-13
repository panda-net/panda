#! /bin/sh
echo "running flowdisector kernel parser basic validation tests"
#flowdis tests
./test_parser -i raw,test-in.raw -c flowdis -o text | diff -u test-out-flowdis.raw -
./test_parser -i pcap,test-in.pcap -c flowdis -o text | diff -u test-out-flowdis.pcap -
./test_parser -i tcpdump,test-in.tcpdump -c flowdis -o text | \
	diff -u test-out-flowdis.tcpdump -
./test_parser -i fuzz -c flowdis -o text < test-in.fuzz | diff -u \
	test-out-flowdis.fuzz -

echo "running panda parser basic validation tests"
#panda tests
./test_parser -i raw,test-in.raw -c panda -o text | diff -u test-out-panda.raw -
./test_parser -i pcap,test-in.pcap -c panda -o text | diff -u test-out-panda.pcap -
./test_parser -i tcpdump,test-in.tcpdump -c panda -o text | \
	diff -u test-out-panda.tcpdump -
./test_parser -i fuzz -c panda -o text < test-in.fuzz | diff -u \
	test-out-panda.fuzz -
