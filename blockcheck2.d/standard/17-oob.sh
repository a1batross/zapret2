. "$TESTDIR/def.inc"

pktws_oob()
{
	# $1 - test function
	# $2 - domain

	local dropacks urp wfempty
	for dropack in '' ':drop_ack'; do
		for urp in b 0 2 midsld; do
			# drop_ack cannot drop anything if it does not come. windows default --wf-tcp-empty=0 stop empty ACKs
			wfempty=
			[ -n "$dropack" -a "$UNAME" = CYGWIN ] && wfempty="--wf-tcp-empty=1"
			pktws_curl_test_update "$1" "$2" $wfempty --in-range=-s1 --lua-desync=oob:urp=$urp$dropack
		done
	done
}

pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_OOB_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	pktws_oob "$@"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_OOB_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_oob "$@"
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls12 "$1" "$2"
}
