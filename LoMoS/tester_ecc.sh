#!/bin/bash
# $1 : number of batches 
# $2 : test per batch 
./compile.sh
if [ -d tests ]; then 
		$((exten = 0 )) 
		while [ -d tests_$((exten)) ]; do
			((exten++))
		done
		mv tests tests_$((exten))
fi 
mkdir tests 

((message_len = 192 ))
echo "Case HEIGHT=$((tree_height)) : LEN=$((message_len))"

echo "Start testing ECDSA..."
for ((batch_c = 0; batch_c < $1; batch_c++ )); do
	echo -n -e " $((batch_c)) / $1\r"
	sudo nice -n -20 ./test_prog eccoo $2  $((message_len)) >> "tests/"ecc_1_$((message_len * 8))".txt"
done



