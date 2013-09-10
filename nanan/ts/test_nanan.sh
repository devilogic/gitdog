#
# 用于调试nanan的加解密是否正确
#

NANAN=../nanan

# 用于生成随机的测试文件
echo $(rand) > testfile
echo $(rand) >> testfile
echo $(rand) >> testfile
echo $(rand) >> testfile
echo $(rand) >> testfile
echo $(rand) >> testfile
echo $(rand) >> testfile

i=0
DECRYPT=

while [ $i -lt 8 ]; do

	echo "$NANAN -1 6 -3 2 -4 0 -5 "$i" -e logic -o ./e_"$i"_62_testfile --silent ./testfile"
	"$NANAN" -1 6 -3 2 -4 0 -5 "$i" -e logic -o ./e_"$i"_62_testfile --silent ./testfile
	if [ $? -eq 0 ]; then
		hash1=$("$NANAN" -3 2 -h ./testfile)
		echo "hash1 = $hash1"

		echo "$NANAN -1 6 -3 2 -4 0 -5 "$i" -d logic -o ./d_"$i"_62_testfile --silent ./e_"$i"_62_testfile"
		"$NANAN" -1 6 -3 2 -4 0 -5 "$i" -d logic -o ./d_"$i"_62_testfile --silent ./e_"$i"_62_testfile
		hash2=$("$NANAN" -3 2 -h ./d_"$i"_62_testfile)
		echo "hash2 = $hash2"
		if [ "$hash1" = "$hash2" ]; then
			echo "mode:$i passed"
		else
			echo "mode:$i not passed"
		fi
	else
		echo "exec nanan failed on test mode:$i"
	fi

	echo "----------"

	let i++

done

exit 0