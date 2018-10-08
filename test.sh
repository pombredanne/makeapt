set -e
rm -rf .makeapt pool
./makeapt.py init

./makeapt.py add xenial:main `ls deb/*.deb | head -n1`
./makeapt.py add xenial:main deb/*.deb
./makeapt.py add xenial:main deb/*.deb
./makeapt.py add xenial:main deb2/*.deb
./makeapt.py group bionic:main '*.deb'
./makeapt.py group lucid:main
./makeapt.py ls 'a*'
./makeapt.py ls 'dc99bf09*'
./makeapt.py rmgroup lucid:main '*amd64*' '*i386*'
./makeapt.py ls lucid:main
