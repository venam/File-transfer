kill $(ps -ef | awk '/storage/&&/python2/{print $2}' | head -n 1)
