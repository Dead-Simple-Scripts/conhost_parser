#! /bin/bash
# Script to automate dumping conhost process memory
clear
echo ""
echo "********************************"
echo "*         Conhost Parser       *"
echo "*      A Volatilty script      *"
echo "*          Version 1           *"
echo "*                              *"
echo "*           by Michael Leclair *"
echo "********************************"
echo ""
echo " For use with the Volatity Framework

Set-Up:
[*]  Use PLIST plugin to identify CONHOST PIDs
[*]  List out CONHOST PIDs in a text file, one PID per line
[*]  Run conhost_parser, Example: ./autoconhost.sh memory_image.dat conhost_pids.txt

What it does:
[*]  Identifies KDBG signature with ImageScan
[*]  Runs memdump for each CONHOST PID
[*]  Strings each memdump *.dmp file
[*]  Deletes the *.dmp file to save disk space
[*]  Runs assorted grep searches against each string file
[***]  Add as many grep searches as you wish
"
echo ""
read -p "Press [Enter] key to start conhost_parser"

#Setting up Volatility to autorun
mkdir logs
mkdir conhost_dumps
exp=conhost_dumps
res=logs
echo ""
echo "Identiying the KDBG signaturewith imageinfo, results pending"
echo ""
date > $res/imageinfo_"$1"_.txt
vol.py -f $1 imageinfo | tee -a $res/imageinfo_$1\_.txt
echo ""
echo "Enter the KDBG signature to use for this memory image, example Win2008R2SP1"
read kdbg
echo ""


#string output directory
mkdir conhost_strings
str_dir=conhost_strings

mkdir autoIOC_results
ioc_res=autoIOC_results

#Dumping CONHOST process space
#Reads the conhost PID file line by line and inserts each line element as the conhost PID variable in Volatility and saves as .dmp file
con_pids=$2
while IFS= read line
do
	vol.py -f $1 --profile=$kdbg memdump -p $line -D $exp
		strings $exp/* > $str_dir/$line.string
		rm $exp/*
		mkdir $ioc_res/$line
		echo "Searching strings for notable file names"
		grep -E -i "\.(exe|bat|dll|py|txt|vbs|jsp)" $str_dir/$line.string | sort | uniq -c | sort -n | grep -E -i "( 1 | 2 | 3 )" | grep -E -i -v "system32|syswow64|program files" > $ioc_res/$line/$line"_notable_files.txt"
		echo "Searching strings for notable commands"
		grep -E -i "commandline:" $str_dir/$line.string > $ioc_res/$line/$line"_commandline.txt"
		grep -E -i "(cmd)" $str_dir/$line.string | sort | uniq -c | sort -n > $ioc_res/$line/$line"_cmd.txt"
		grep -E -i -B 1 -A 30 "(^logname)" $str_dir/$line.string | grep -E -i "new process name|process command line" > $ioc_res/$line/$line"_proc_cmd_line.txt"
		grep -E -i -A 30 "event stanza" $str_dir/$line.string > $ioc_res/$line/$line"_event_stanza.txt"
		grep -E -i -B 1 -A 30 "(^logname)" $str_dir/$line.string > $ioc_res/$line/$line"_log_entry.txt"
		grep -E -i "(powershell.exe)" $str_dir/$line.string > $ioc_res/$line/$line"_powershell.txt"
		grep -E -i "start:" $str_dir/$line.string > $ioc_res/$line/$line"_start.txt"
done < "$con_pids"

echo "conhost_parser completed"
