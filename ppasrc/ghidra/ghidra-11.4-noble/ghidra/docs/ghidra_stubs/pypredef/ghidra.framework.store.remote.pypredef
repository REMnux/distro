from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.client
import ghidra.framework.store
import java.lang # type: ignore


class RemoteFolderItem(ghidra.framework.store.FolderItem):
    """
    ``RemoteFolderItem`` provides an abstract FolderItem implementation
    for an item contained within a remote Repository.
    """

    class_: typing.ClassVar[java.lang.Class]


class RemoteDatabaseItem(RemoteFolderItem, ghidra.framework.store.DatabaseItem):
    """
    ``RemoteDatabaseItem`` provides a FolderItem implementation
    for a remote database.  This item wraps an underlying versioned database
    which corresponds to a repository item.
    """

    class_: typing.ClassVar[java.lang.Class]


class RemoteFileSystem(ghidra.framework.store.FileSystem, ghidra.framework.client.RemoteAdapterListener):
    """
    ``RemoteFileSystem`` provides access to versioned FolderItem's which 
    exist within a Repository-based directory structure.  FolderItem
    caching is provided by the remote implementation which is intended
    to be shared across multiple clients.
     
    
    FolderItem's must be checked-out to create new versions.
     
    
    FileSystemListener's will be notified of all changes made 
    within the Repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, repository: ghidra.framework.client.RepositoryAdapter):
        """
        Construct a new remote file system which corresponds to a remote repository.
        
        :param ghidra.framework.client.RepositoryAdapter repository: remote Repository
        """



__all__ = ["RemoteFolderItem", "RemoteDatabaseItem", "RemoteFileSystem"]
