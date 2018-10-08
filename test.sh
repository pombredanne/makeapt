set -e
rm -rf .makeapt pool
./makeapt.py init

./makeapt.py add `ls deb/*.deb | head -n1`
./makeapt.py add deb/*.deb
./makeapt.py add deb/*.deb
./makeapt.py group bionic:main '*.deb'
./makeapt.py group lucid:main
