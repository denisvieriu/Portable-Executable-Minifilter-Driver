# Portable-Executable-Minifilter-Driver

An simple PE dumper transformed as a scanner for a specific virus who corrupts PE format.
A separate mini filter driver is deployed, and for every access of a file, the driver
send to the PE Scanner the context to scan. If the PE contains traces of the specific VIRUS, 
it signals back to the mini filter an result blocking the file immediately.

The program can be run from CMD/POWERSHELL and it takes as arguments the folder to scan, if used as 
a PE DUMPER, otherwise, when used for virus scan, the Mini Filter driver must be deployed first.

The folder is scanned in the following order:
If a file is found, the file is immediately passed to a separate thread to scan it. The number of threads is 
defined by: #define MAX_THREADS <ThreadToRun>. To prevent deadlocks, events are used. When a filename is retrieved,
it is pushed in the LIST_ENTRY and a SetEvent is made, to signal the running threads that a file is ready to be scanned.
Almost all threads scan the same number of files (no thread is getting other's thread job)