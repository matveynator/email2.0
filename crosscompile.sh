version="0.1"

for os in linux freebsd netbsd openbsd plan9;
do
  for arch in amd64 "386" arm 
  do
    mkdir -p ../../download/$os/$arch/$version
    echo "GOOS=$os GOARCH=$arch $opt go build -o ../../download/$os/$arch/$version/rigel rigel.go"
    GOOS=$os GOARCH=$arch $opt go build -o ../../download/$os/$arch/$version/rigel rigel.go
  done
done

#mac
for os in darwin;
do
  for arch in amd64 "386"
  do
    mkdir -p ../../download/mac/$arch/$version
    echo "GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o ../../download/mac/$arch/$version/rigel rigel.go"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o ../../download/mac/$arch/$version/rigel rigel.go
  done
done

#dragonfly
for os in dragonfly;
do
  for arch in amd64
  do
    mkdir -p ../../download/$os/$arch/$version
    echo "GOOS=$os GOARCH=$arch go build -o ../../download/$os/$arch/$version/rigel rigel.go"
    GOOS=$os GOARCH=$arch go build -o ../../download/$os/$arch/$version/rigel rigel.go
  done
done

#windows
for os in windows;
do
  for arch in amd64 "386"
  do
    mkdir -p ../../download/$os/$arch/$version
    echo "GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o ../../download/$os/$arch/$version/rigel.exe rigel.go"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o ../../download/$os/$arch/$version/rigel.exe rigel.go
  done
done

rsync -avP --delete ../../download root@rigel.email:/home/rigel/public_html/
