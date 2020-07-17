#!/usr/bin/env bash

# This command will guarantee 43 random alpha numeric characters (62 char set) 
# (338 bits), with an equivalent entropy of approximately log2(62^43) ≈ 256 bits.

# For more details on the commands see post at 
# https://security.stackexchange.com/questions/183948/unix-command-to-generate-cryptographically-secure-random-string
# and 
# https://en.wikipedia.org/wiki//dev/random

paranoid=false

for i in "$@"
	do
	case $i in
		# -p=*|--paranoid=*)
		# paranoid="${i#*=}"
		# shift # past argument=value
		-p|--paranoid)
		paranoid=true
		shift # past argument with no value
		;;
		*)
		# unknown option
		;;
	esac
done

if [ $paranoid = true ]; then
	# This may take a very long time depending on your system load / drivers, I/O etc
	echo "You selected /dev/random RNG - this will take a REALLY long time..."
	LC_ALL=C tr -dc '[:alnum:]' < /dev/random | head -c43 > trngseed.bin
else
	LC_ALL=C tr -dc '[:alnum:]' < /dev/urandom | head -c43 > trngseed.bin
fi

echo "Seed generated at trngseed.bin"

exit 0