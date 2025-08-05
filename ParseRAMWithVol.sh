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
    mkdir $foldername
    echo "- Created folder $foldername, parsed files will be placed in that folder"
    echo
    echo "Creating strings file with 8 char minimum as strings.txt ... (this could take some time)"
    strings -a -t d -n 8 $1 > $foldername/strings.txt
    echo "Creating command line dump as cdmline.txt ... 1/24"
    vol -f $1   windows.cmdline > $foldername/cmdline.txt
    echo
    echo "Creating DLL list into dlllist.txt ... 2/24"
    vol -f $1    windows.dlllist > $foldername/dlllist.txt
    echo
    echo "Creating driver list into driverlist.txt ... 3/24"
    vol -f $1   windows.driverscan > $foldername/driverlist.txt
    echo
    echo "Creating list of environment variables as envlist.txt ... 4/24"
    vol -f $1   windows.envars > $foldername/envlist.txt
    echo
    echo "Creating list of files in memory as filelist.txt .... 5/24"
    vol -f $1   windows.filescan > $foldername/filelist.txt
    echo
    echo "Creating list of owner SIDs for each process as ownersidslist.txt ... 6/24"
    vol -f $1   windows.getsids > $foldername/ownersidslist.txt
    echo
    echo "Creating list of open file handles into handleslist.txt ... 7/24"
    vol -f $1   windows.handles > $foldername/handleslist.txt
    echo
    echo "Creating list of memory ranges with potentially injected code as malmemcode.txt ... 8/24 (this could take some time)"
    vol -f $1   windows.malware.malfind > $foldername/malmemcode.txt
    echo 
    echo "Creating list of potentially injected by rootkit drivers as rootkitsdrivers.txt ... 9/24"
    vol -f $1   windows.malware.drivermodule > $foldername/rootkitsdrivers.txt
    echo
    echo "Creating list of potentially malware hollowed proccess as malhollow.txt ... 10/24"
    vol -f $1   windows.malware.hollowprocesses > $foldername/malhollow.txt
    echo
    echo "Creating list of process that could be malware set to delete on close as maldelete.txt ... 11/24"
    vol -f $1   windows.malware.processghosting > $foldername/maldelete.txt
    echo
    echo "Creating list of services which could indicate rootkits as rootkits.txt ... 12/24"
    vol -f $1   windows.malware.svcdiff > $foldername/rootkits.txt
    echo
    echo "Scanning MBR as mbrscan.txt ... 13/24 (this could take some time)"
    vol -f $1   windows.mbrscan > $foldername/mbrscan.txt
    echo
    echo "Creating memory map as memmap.txt ... 14/24 (this could take some time)"
    vol -f $1   windows.memmap > $foldername/memmap.txt
    echo
    echo "Creating process list as processlist.txt ... 15/24"
    vol -f $1   windows.pslist > $foldername/processlist.txt
    echo
    echo "Creating process scan as processscan.txt ... 16/24"
    vol -f $1   windows.psscan > $foldername/rocessscan.txt
    echo
    echo "Creating process tree as processtree.txt ... 17/24"
    vol -f $1   windows.pstree > $foldername/processtree.txt
    echo
    echo "Extracting process execution cache as execcahe.txt ... 18/24"
    vol -f $1   windows.registry.amcache > $foldername/execcahe.txt
    echo
    echo "Creating list of scheduled tasks for loaded registry hive as tasks.txt ... 19/24"
    vol -f $1   windows.registry.scheduled_tasks > $foldername/tasks.txt
    echo
    echo "Creating list of active sessions as sessions.txt ... 20/24"
    vol -f $1   windows.sessions > $foldername/sessions.txt
    echo
    echo "Extracting process strings from memory as processstrings.txt ... 21/24 (this could take some time)"
    vol -f $1   windows.strings > $foldername/processstrings.txt --strings-file=$foldername/strings.txt
    echo
    echo "Performing root kit service comparison as rootkitsvcs.txt ... 22/24"
    vol -f $1   windows.svcdiff > $foldername/rootkitsvcs.txt
    echo
    echo "Extracting running services as services.txt ... 23/24"
    vol -f $1   windows.svcscan > $foldername/services.txt
    echo
    echo "Extracting TruCrypt passwords in memory as trucrypt.txt ... 24/24"
    vol -f $1   windows.truecrypt > $foldername/trucrypt.txt
    echo
    echo "Done."    
  else
    echo "- file not found!"
  fi
fi
