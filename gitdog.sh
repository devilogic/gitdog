#
# gitdog [options]
# [options]
# help 帮助
# make key [username] [email] 制作公私钥对
# sign [license1,...] 对授权文件进行签名
# import license [license1,...] 导入他人的授权文件
# import owner license [license] 导入owner的授权文件
# import my license [license] 导入当前项目自己的授权文件
# export license [path] 导出自己的授权文件
# init 初始化项目(一旦初始化一个项目则自动成为此项目的owner)
#

usage() {
	echo "gitdog command [options]"
	echo "------------------------------"
	echo "make key <username> <email> 制作公私钥对"
	echo "sign [license1,...] 对授权文件进行签名"
	echo "import license [license1,...] 导入他人的授权文件"
	echo "import owner license [license] 导入owner的授权文件"
	echo "import my license [license] 导入当前项目自己的授权文件"
	echo "export license [path] 导出自己的授权文件"
	echo "init 初始化项目(一旦初始化一个项目则自动成为此项目的owner)"
	echo "clone 克隆项目(一旦克隆成功则自行生成自己的授权文件)"
	echo ""
}

gitdog_init() {

	if [ -d ".gitdog" ]; then
		exit 0
	fi

	# 生成工作目录
	mkdir .gitdog

	# 生成授权文件目录
	mkdir .gitdog/license
	mkdir .gitdog/license/s
	mkdir .gitdog/license/a
	mkdir .gitdog/license/c

	# 生成源文件路径
	mkdir .gitdog/x

	# 生成备份文件路径
	mkdir .gitdog/backup

	# 切换到源文件路径中，进行git init
	cd ./.gitdog/x
	git init
	cd "$gWorkDir"

	# 生成拥有者授权文件
	
	# 将授权文件放入到当前授权文件池的s目录中

	return 0
}

gitdog_clone() {
	local curr=$(pwd)

	if [ $# > 1 ]; then
		mkdir "$2"
		cd "$2"
	fi

	# 首先利用git将仓库签出来到缓存中
	local tmpdir=$(rand)
	cd "$gTmp/$tmpdir"
	git clone $1 .
	
	cd "$curr"
	return 0
}

# 导出命令
gitdog_export() {
	for license in $(ls "$gMyLicense")
	do
		cp "$gMyLicense/$license" "$1/$license"
		break
	done

	return 0
}

# 导入多个其他人的证书
gitdog_import_license() {
	for license_others in $@
	do
		if [ -n $license_others ] && [ -f $lincense_others ]; then
			#
			# 导入到当前工程的授权文件必须要带有owner的签名
			# 使用salamis验证签名
			# 并使用计算出的MD5重新命名授权文件
			#

			local sign=$(gGitdog get sign "$license_others")
			if [ -n "$sign" ]; then
				# 签名不为空,获取证书公钥部分
				local x=$(gGitdog get public "$license_others")
				local b=$(gSalamis verify )
			fi

		fi
	done
	return 0
}

gitdog_import_my() {
	return 0
}

gitdog_import_owner() {
	# 检测此授权文件是否被owner进行签名
	# 检测此授权文件是否是当前项目的owner
	return 0
}

# 检测参数是否为空
if [ $# = 0 ]; then
	usage
	exit 1
fi

# 配置全局环境变量
gGit="$GITDOG_GIT"
gSalamis="$GITDOG_DIR/salamis.exe"
gGitdog="$GITDOG_DIR/gitdog.exe"
gWorkDir=$(pwd)
gBaseDir=$(printf "%s/.gitdog" "$gWorkDir")
gMyLicense=$(printf "%s/.gitdog/license/a" "$gWorkDir")
gOtherLicense=$(printf "%s/.gitdog/license/c" "$gWorkDir")
gOwnerLicense=$(printf "%s/.gitdog/license/s" "$gWorkDir")
gRealDir=$(printf "%s/.gitdog/x" "$gWorkDir")
gConfigDir=$(printf "%s/.gitdog" "$HOME")
gTmp=$(printf "%s/.gitdog_cache" "$HOME")

# 打印目录
# echo "workdir = $gWorkDir"
# echo "realdir = $gRealDir"
# exit 0

# 依次检查命令
for arg in $@
do
	# 检查参数是否为空
	if [ -z "$arg" ]; then
		continue
	fi
	
	# 检查参数
	case "$arg" in
		"make")
			if [ "$2" = "key" ]; then
				# 移动到第二个参数 key
				shift
				exec "$gSalamis make key ecc $3"
			elif [ "$2" == "license" ]; then
				# 移动到第二个参数 license
				exec "$gGitdog $@"
			else
				echo "[-] 参数只能使用\"key\"与\"license\""
				exit 1
			fi
		;;
		"sign")
			shift
			exec "$gRealdir $@"
		;;
		"import")
			case "$2" in
				"license")
					shift
					shift
					ret=$(gitdog_import_license $@)
					echo "[+] 导入他人授权文件成功"
					exit 0
				;;
				"my")
					ret=$(gitdog_import_my $3)
					echo "[+] 导入自身授权文件成功"
					exit 0
				;;
				"owner")
					ret=$(gitdog_import_owner $3)
					echo "[+] 导入拥有者授权文件成功"
					exit 0
				;;
				*)
					echo "[-] 无效的导入参数"
					exit 1
				;;
			esac
		;;	
		"export")
			if [ "$2" != "license" ]; then
				echo "第二个参数必须为license"
				exit 1
			else
				ret=$(gitdog_export $3)
				echo "[+] 导出自身授权文件成功"
				exit 0
			fi
		;;
		"init")
			ret=$(gitdog_init)
			echo "[+] 初始化成功"
			exit 0
		;;
		"clone")
			ret=$(gitdog_clone)
			echo "[+] 克隆仓库成功"
			exit 0
		;;
		*)
			cd $gRealDir
			ret=$(git $@)
			cd $gWorkDir
			exit 0
		;;
	esac
done

