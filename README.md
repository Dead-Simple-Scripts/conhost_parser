# conhost_parser
Script to dump and process CONHOST memory space

For use with the Volatity Framework

Set-Up:

Use PLIST plugin to identify CONHOST PIDs

List out CONHOST PIDs in a text file, one PID per line

Run conhost_parser, Example: ./autoconhost.sh memory_image.dat conhost_pids.txt


What it does:

Identifies KDBG signature with ImageScan

Runs memdump for each CONHOST PID

Strings each memdump *.dmp file

Deletes the *.dmp file to save disk space

Runs assorted grep searches against each string file

Add as many grep searches as you wish

