#!/bin/bash
# next time correct the messagel lengths.
# $1 : number of batches 
# $2 : test per batch 
if [ -d tests ]; then 
		$((exten = 0 )) 
		while [ -d tests_$((exten)) ]; do
			((exten++))
		done
		mv tests tests_$((exten))
fi 
mkdir tests 

(( key_len = 2048 ))
for ((tree_height = 6; tree_height <= 13; tree_height++ )); do 
	((upper_msg = 12 ))
	if ((tree_height < 12 )); then
		((upper_msg = tree_height )) 
	fi
	for ((log_msg_len = 0; log_msg_len < upper_msg; log_msg_len++ )); do 
		((message_len = 2 ** log_msg_len ))
		echo "Case HEIGHT=$((tree_height)) : LEN=$((message_len))"
		# echo Start testing init...
		# for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			# nice -n -20 test_prog ini $2 $tree_height
		# done 
		echo "Start testing build & root sign..."
		for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			echo -n -e " $((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog bld $2 $((tree_height)) $((message_len)) >> "tests/"bld_$((tree_height))_$((message_len))".txt"
			sudo nice -n -20 ./test_prog sgn $2 >> "tests/"sgn_$((tree_height))_$((message_len))".txt"
		done
	
		echo "Start testing DSA..."
		for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			echo -n -e " $((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog dsa $2  $((message_len)) >> "tests/"dsa_$((tree_height))_$((message_len))".txt"
		done
		echo "Start testing ECDSA..."
		for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			echo -n -e " $((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog eccoo $2  $((message_len)) >> "tests/"eccoo_$((tree_height))_$((message_len))".txt"
		done
	
		echo "Start testing generate & verification..."
		for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			echo -n -e "$((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog gen $2 $((tree_height)) $((message_len)) >> "tests/"gen_$((tree_height))_$((message_len))."txt"
			echo -n -e " $((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog ver >> "tests/"ver_$((tree_height))_$((message_len))".txt"
		done


		echo "Start testing generate & efficient verification..."
		for ((batch_c = 0; batch_c < $1; batch_c++ )); do
			echo -n -e " $((batch_c)) / $1\r"
			sudo nice -n -20 ./test_prog gen $2 $((tree_height)) $((message_len)) >> "tests/"gen_$((tree_height))_$((message_len))."txt"
			sudo nice -n -20 ./test_prog vff >> "tests/"vff_$((tree_height))_$((message_len))".txt"
		done

		

		#./test_prog 10 $((tree_height)) $((message_len)) $((key_len))
		#./test_prog 100 $((tree_height)) $((message_len)) $((key_len))
		#echo Done\ $((tree_height)), $((message_len))
	done
done 
