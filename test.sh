set -e
rm -rf .makeapt pool
./makeapt.py init
./makeapt.py add deb/*.deb
./makeapt.py add deb/*.deb
