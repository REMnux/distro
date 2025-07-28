First of all
============

* For feedback, discussions, bugreports, feature requests, etc. feel free to join ProcDOT forum (https://groups.google.com/forum/#!forum/procdot)
  or drop an email: chrisu@procdot.com or team@cert.at

* A number of tutorial videos have been created for you to get familiar with ProcDOT. Watching them is highly recommended to get the most out of ProcDOT.

* Furthermore you will find a cheatsheet on the website as well as onboard of ProcDOT which sums up the most important things.

* There's a FAQ section on the website. In case of an issue please check it.

* Follow ProcDOT's Twitter channel to be up to date to latest news on ProcDOT (https://twitter.com/ProcDOT).


Prerequisites
=============

ProcDOT depends on third party software and therefore needs the following software pre-installed to work properly:

* Graphviz-Suite
  Windows: Get the installer and run it.
           (http://www.graphviz.org/pub/graphviz/stable/windows/graphviz-2.28.0.msi)
  Linux:   Use package manager to install.

* Windump/Tcpdump
  Windows: Get the executable and put it in any location.
           (http://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe)
  Linux:   Use package manager to install.
           Important: ProcDOT needs tcpdump to have executable permissions for everyone otherwise tcpdump won't be callable!


Important steps to follow
=========================

You need to adjust Procmon's configuration (actually for each Procmon installation you want to be compatible to ProcDOT) to match ProcDOT's needs.
Therefore, in Procmon ...
* disable (uncheck) "Show Resolved Network Addresses" (Options)
* disable (uncheck) "Enable Advanced Output" (Filter)
* adjust the displayed columns (Options > Select Columns ...)
  * to not show the "Sequence" column
  * to show the "Thread ID" column

Furthermore ProcDOT needs to know where its third party tools are located.
Hence, in ProcDOT ...
* choose your Windump/Tcpdump (windump.exe/tcpdump)) executable as fully qualified path (ProcDOT options)
* choose your Dot executable (dot.exe) as fully qualified path (ProcDOT options)


On Linux ...
============

... be sure to set the executable-flag for executables!
... and please install libwebkitgtk-3.o-dev if you encounter issues like "error while loading shared libraries: libwebkitgtk-3.0.so.0: cannot open shared object file: No such file or directory".


Plugins ...
===========

Since build 56 all relevant plugins are bundled with ProcDOT.
For updates on the plugins please visit the according author's plugin pages which can be found on http://procdot.com/downloadplugins.htm ...


Quickstart into ProcDOT
=======================

1) Select your logfiles (Sad but true, the specs for Procmon's native file-format (.PML) are not (publicly) available. Therefore you have to export your .PML file to .CSV which can be easily done via the "Save" menuitem in Procmon. Be sure to select "all events".)
2) Choose graphing mode (no paths, compressed)
3) Select the first relevant (malicious) process (launching process)
4) Click "Refresh"
