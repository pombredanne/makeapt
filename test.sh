set -e
rm -rf .makeapt pool dists
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
./makeapt.py rmgroup bionic:main 'dc99bf09*'
./makeapt.py rmgroup xenial:main 'dc99bf09*'
./makeapt.py rmgroup bionic:main 'c96f389e*'
./makeapt.py rmgroup xenial:main 'c96f389e*'
./makeapt.py config origin 'My Origin'
./makeapt.py config label 'My Label'
./makeapt.py config gpg_key_id 48CA8420
./makeapt.py index
