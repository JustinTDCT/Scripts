#! /bin/bash

echo "Creating command line dump as cdmline.txt ..."
vol -f ramdump1.raw -v  windows.cmdline > cmdline.txt
eecho
echo "Creating DLL list into dlllist.txt ..."
vol -f ramdump1.raw -v   windows.dlllist > dlllist.txt
echo
echo "Creating driver list into driverlist.txt ..."
vol -f ramdump1.raw -v  windows.driverscan > driverlist.txt
echo
echo "Creating list of environment variables as envlist.txt ..."
vol -f ramdump1.raw -v  windows.envars > envlist.txt
echo
echo "Creating list of files in memory as filelist.txt ...."
vol -f ramdump1.raw -v  windows.filescan > filelist.txt
echo
echo "Creating list of owner SIDs for each process as ownersidslist.txt ..."
vol -f ramdump1.raw -v  windows.getsids > ownersidslist.txt
echo
echo "Creating list of open file handles into handleslist.txt ..."
vol -f ramdump1.raw -v  windows.handles > handleslist.txt
echo
echo "Creating list of memory ranges with potentially injected code as malmemcode.txt ..."
vol -f ramdump1.raw -v  windows.malfind > malmemcode.txt
echo 
echo "Creating list of potentially injected by rootkit drivers as rootkitsdrivers.txt ..."
vol -f ramdump1.raw -v  windows.malware.drivermodule > rootkitsdrivers.txt
echo
echo "Creating list of potentially malware hollowed proccess as malhollow.txt ..."
vol -f ramdump1.raw -v  windows.malware.hollowprocesses > malhollow.txt
echo
echo "Creating list of process that could be malware set to delete on close as maldelete.txt ..."
vol -f ramdump1.raw -v  windows.malware.processghosting > maldelete.txt
echo
echo "Creating list of services which could indicate rootkits as rootkits.txt ..."
vol -f ramdump1.raw -v  windows.malware.svcdiff > rootkits.txt
echo
echo "Scanning MBR as mbrscan.txt ..."
vol -f ramdump1.raw -v  windows.mbrscan > mbrscan.txt
echo
echo "Creating memory map as memmap.txt ..."
vol -f ramdump1.raw -v  windows.memmap > memmap.txt
echo
echo "Creating process list as processlist.txt ..."
vol -f ramdump1.raw -v  windows.pslist > processlist.txt
echo
echo "Creating process scan as processscan.txt ..."
vol -f ramdump1.raw -v  windows.psscan > rocessscan.txt
echo
echo "Creating process tree as processtree.txt ..."
vol -f ramdump1.raw -v  windows.pstree > processtree.txt
echo
echo "Extracting process execution cache as execcahe.txt ..."
vol -f ramdump1.raw -v  windows.registry.amcache > execcahe.txt
echo
echo "Creating list of scheduled tasks for loaded registry hive as tasks.txt ..."
vol -f ramdump1.raw -v  windows.registry.scheduled_tasks > tasks.txt
echo
echo "Creating list of active sessions as sessions.txt ..."
vol -f ramdump1.raw -v  windows.sessions > sessions.txt
echo
echo "Extracting process strings from memory as processstrings.txt ..."
vol -f ramdump1.raw -v  windows.strings > processstrings.txt
echo
echo "Performing root kit service comparison as rootkitsvcs.txt ..."
vol -f ramdump1.raw -v  windows.svcdiff > rootkitsvcs.txt
echo
echo "Extracting running services as services.txt ..."
vol -f ramdump1.raw -v  windows.svcscan > services.txt
echo
echo "Extracting TruCrypt passwords in memory as trucrypt.txt ..."
vol -f ramdump1.raw -v  windows.truecrypt > trucrypt.txt
echo
echo "Done."
