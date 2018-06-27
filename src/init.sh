#!/bin/bash


. $1/tpm_emulator.config

#echo $1

#echo "Content of VARIABLE1 is $server_port"

current_dir=$(pwd)


cd $utils_address # moving to folder

#echo $TPM_SERVER_PORT

export TPM_SERVER_PORT="$server_port"
export TPM_SERVER_NAME="$server_name"


#echo $current_dir



root_key_file="$current_dir/.rootkey.seal"
own_pass="$password"
srk_pass="$password"

return_var=""

test_output="$current_dir/my.txt"

if [ "$2" = "seal" ]
then

	if [ ! -e $root_key_file ]; then
		touch $root_key_file
	fi

	./clearown -pwdo $own_pass
	./tpminit
	./tpmbios
	./tpminit
	./tpmbios
	./takeown -pwdo $own_pass -pwds $srk_pass

	./sealfile -hk 40000000 -if <(echo $3) -of $root_key_file -pwdk $srk_pass
elif [ "$2" = "unseal" ]
then
	return_var=$(./unsealfile -hk 40000000 -if $root_key_file -pwdk $srk_pass -of /dev/stdout)

fi


#echo "printing output"
echo $return_var



