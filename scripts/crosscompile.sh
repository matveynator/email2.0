#!/bin/bash
version="0.2-001"
git_root_path=`git rev-parse --show-toplevel`
execution_file=rigel
cd ${git_root_path}/scripts
for os in linux freebsd netbsd openbsd aix android illumos ios solaris plan9 darwin dragonfly js windows ;
#for os in darwin;
do
	for arch in "amd64" "386" "arm" "arm64" "mips64" "mips64le" "mips" "mipsle" "ppc64" "ppc64le" "riscv64" "s390x" "wasm"
	do
		target_os_name=${os}
		[ "$os" == "windows" ] && execution_file="rigel.exe"
		[ "$os" == "js" ] && execution_file="rigel.js"
		[ "$os" == "darwin" ] && target_os_name="mac"
		
		mkdir -p ../download/${version}/${target_os_name}/${arch}
		GOOS=${os} GOARCH=${arch} go build -ldflags "-X main.Version=${version}" -o ../download/${version}/${target_os_name}/${arch}/${execution_file} ../rigel.go &> /dev/null
		if [ "$?" != "0" ]
		#if compilation failed - remove folders - else copy config file.
		then
		  rm -rf ../download/${version}/${target_os_name}/${arch}
		else
		  echo "GOOS=${os} GOARCH=${arch} go build -ldflags "-X main.Version=${version}" -o ../download/${version}/${target_os_name}/${arch}/${execution_file} ../rigel.go"
		fi
	done
done

rm -f ../download/latest
ln -s ../download/${version} ../download/latest
rsync -avP ../download root@rigel.email:/home/rigel/public_html/
