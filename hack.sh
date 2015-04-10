#!/bin/bash

rm -rf webpage*
wget -p -k "$1"
echo "$1"
mv "$1" webpage

if [ -d webpage ]; then
	mv $(find webpage -name "*.html") webpage.html
else
	mv webpage webpage.html
fi

echo '<script>alert("Hacked!")</script>' >> webpage.html
rm -rf webpage
