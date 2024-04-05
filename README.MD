# Qumulo-Lock-Manager

This script provides a web based GUI to list and close SMB locks on a Qumulo cluster via the Qumulo REST API.  

# -- *Beta* --

## This app requires a running Redis Server instance!

Installation for local test hosting:

- Tested with Python 3.11.6
- Copy all files locally
- Edit async_main.conf with your information
- Install requirements.txt
- Fire up Redis server, the local hosted version of the script expects it to be at 127.0.0.1:6379

Running the Lock Manager:

Note that the port :4000 can be whatever you'd like.  `--workers 4` can be a lower value if you'd like.

`hypercorn async_main:app --workers 4 --bind 127.0.0.1:4000`


## Why close file handles and what happens on the client when a file handle is closed?

The SMB protocol provides a system of locks which allow a client to set what kind of access it wants to a file stored in an SMB server.  Qumulo
supports most of those locks, such as Exclusive Read or Exclusive Write, but in a shared envionment this could lead to situations where users are
prevented from saving files or accessing files that others have locked.

In those situations the storage administrator could opt to force the closure of this file handle to allow other users access to the file.

Some very common example scenarios are when a user can't save an Excel spreasheet that another user has opened, or when the Mac Finder's Quick Look file previewer
triggered by one user prevents another user from saving a Photoshop or other graphics file.

Selecting and closing file handles via this app will close the handle on the Qumulo cluster side, but the client will still have the file open on its end and there will be no
perceptible change from the perspective of the client holding the lock.  

The client will be left with a "stale" local version of the file that might be out of sync with the version stored in the cluster.  This client will then need to close the file 
locally and reopen it from the Qumulo cluster to get back in sync with the stored version of the file.  

**_There is a possibility that the user which held the lock could lose work in progress if the file handle is closed before the file has been saved_**, so use caution when closing file handles!

Run it with: `hypercorn async_main:app --workers 4 --bind 127.0.0.1:4000` or whatever IP:port you want

Note that the async version is considerably different and uses Quart instead of Flask, so check your dependencies.


