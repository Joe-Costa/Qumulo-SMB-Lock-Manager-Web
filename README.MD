# Qumulo-Lock-Manager

This script provides a web based GUI to list and close SMB locks on a Qumulo cluster via the Qumulo REST API.  

# -- *Beta* --


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

## Why use this tool vs the fsmgmt.msc tool in Windows?

The FS Management Tool in Windows, beyond not being available for Mac or Linux clients, can only display up to 10k locks or file handles which is a limit that is often exceeded among Qumulo customers while this tool has been field-tested to handle in excess of 32k locks.

Please note that if you expect to regularly handle such large numbers of locks that the SMB Lock Manager should be deployed in a network location that is as close as possible to the Qumulo cluster for the
best possible performance.  

Also please be aware that retrieving and displaying 20k or more locks could take several minutes depending on the network latency between the Lock Manager and the Qumulo cluster.

## RBAC privileges required

This script requires a valid session token for a user with the following RBAC privileges:

`['PRIVILEGE_FS_LOCK_READ', 'PRIVILEGE_SMB_FILE_HANDLE_READ', 'PRIVILEGE_SMB_FILE_HANDLE_WRITE', 'PRIVILEGE_IDENTITY_READ']`

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://care.qumulo.com/hc/en-us/articles/360004600994-Authenticating-with-Qumulo-s-REST-API#acquiring-a-bearer-token-by-using-the-web-ui-0-3) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

## Installation:

Three different install methods are provided:

[A Docker deployment using `docker-compose`](DOCKER)

[A Kubernetes deployment](K8S)

[The source file for anyone want to build their own Docker image or self hosting](src)

