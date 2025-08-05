#!/bin/bash

if [ $# -eq 0 ]; then
  echo "No arguments provided."
elif [ $# -gt 1 ]; then
  echo "Too many arguments provided."
else
  clear
  echo "Checking if file $1 exists ..."
  if [ -f "$1" ]; then
    echo "- file found."
    echo "Making new folder for this dump file ..."
    filename="$1"
    foldername="${filename%.*}"
    foldername="DUMP_$foldername"
    echo "$foldername"
  else
    echo "- file not found!"
  fi
fi
