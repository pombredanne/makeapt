set -e
rm -rf .makeapt pool
./makeapt.py init

./makeapt.py add lucid `ls deb/*.deb | head -n1`
./makeapt.py add bionic:main deb/*.deb
./makeapt.py add xenial:main deb/*.deb
