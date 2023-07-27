#!/bin/sh

case "$1" in
	*-src)
		;;
	python3-certifi)
		BUNDLE=$(python3 -m certifi) || {
			echo "Failed to run the certfi module script.  Exit status=$?." >&2
			echo "Output='$BUNDLE'" >&2
			exit 1
		}
		[ -f "$BUNDLE" ] || {
			echo "Bundle file '$BUNDLE' not found." >&2
			exit 1
		}
		;;
	*)
		echo "Unexpected package '$1'"
		exit 1
		;;
esac
