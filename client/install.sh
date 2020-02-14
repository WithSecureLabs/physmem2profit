#!/bin/bash

OLDDIR="$(pwd)"
NEWDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $NEWDIR
if [ "$(ls -A rekall)" ]
then
	sudo apt install -y gcc git python3-pip virtualenv libncurses5-dev fuse
	virtualenv -p python3 .env
	source .env/bin/activate
	pip install -r requirements.txt
else
	echo "Rekall repository is empty. Please use recursive initialization of submodules"
fi
cd $OLDDIR