from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.lsh.vector
import ghidra
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.framework
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import utility.application


class HeadlessBSimApplicationConfiguration(ghidra.framework.ApplicationConfiguration):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IterateRepository(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def process(self, ghidraURL: java.net.URL, monitor: ghidra.util.task.TaskMonitor):
        """
        Process the specified repository URL
        
        :param java.net.URL ghidraURL: ghidra URL for existing server repository and optional
        folder path
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises java.lang.Exception: if an error occurs during processing
        :raises CancelledException: if processing is cancelled
        """


class BSimLaunchable(ghidra.GhidraLaunchable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor for launching from the console
        """

    @staticmethod
    def initializeApplication(layout: utility.application.ApplicationLayout, type: typing.Union[jpype.JInt, int], connectingUserName: typing.Union[java.lang.String, str], certPath: typing.Union[java.lang.String, str]):
        """
        From a cold start, initialize the Ghidra application to different stages, based on future requirements
        
        :param utility.application.ApplicationLayout layout: application layout
        :param jpype.JInt or int type: is an integer indicating how much to initialize
                0 - limited initialization, enough simple execution and logging
                1 - full initialization of ghidra for module path info and initialization
                2 - same as #1 with class search for extensions
        :param java.lang.String or str connectingUserName: default user name for server connections
        :param java.lang.String or str certPath: PKI certificate path
        :raises IOException: if there is a problem initializing the headless authenticator
        """

    @typing.overload
    def run(self, params: jpype.JArray[java.lang.String], monitor: ghidra.util.task.TaskMonitor):
        """
        Runs the command specified by the given set of params.
        
        :param jpype.JArray[java.lang.String] params: the parameters specifying the command
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IllegalArgumentException: if invalid params have been specified
        :raises java.lang.Exception: if there's an error during the operation
        :raises CancelledException: if processing is cancelled
        """

    @typing.overload
    def run(self, params: jpype.JArray[java.lang.String]):
        """
        Runs the command specified by the given set of params.
        
        :param jpype.JArray[java.lang.String] params: the parameters specifying the command
        :raises java.lang.Exception: when initializing the application or executing the command
        """


class BulkSignatures(java.lang.AutoCloseable):

    @typing.type_check_only
    class UpdateRepository(IterateRepository):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, outdir: jpype.protocol.SupportsPath, rp: typing.Union[java.lang.String, str], owrite: typing.Union[jpype.JBoolean, bool], i: ghidra.features.bsim.query.description.DatabaseInformation, vFactory: generic.lsh.vector.LSHVectorFactory):
            ...


    @typing.type_check_only
    class SignatureRepository(IterateRepository):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, outdir: jpype.protocol.SupportsPath, rp: typing.Union[java.lang.String, str], owrite: typing.Union[jpype.JBoolean, bool], i: ghidra.features.bsim.query.description.DatabaseInformation, vFactory: generic.lsh.vector.LSHVectorFactory):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bsimServerInfo: ghidra.features.bsim.query.BSimServerInfo, connectingUserName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.features.bsim.query.BSimServerInfo bsimServerInfo: the BSim database server info.  May be ``null`` if use limited to
        signature and update generation only (based upon configuration template).
        :param java.lang.String or str connectingUserName: user name to use for BSim server authentication.  May be null if
        not required or default should be used (see :meth:`ClientUtil.getUserName() <ClientUtil.getUserName>`).  If specified
        a new :obj:`BSimServerInfo` instance will be created with the user information set.  This
        argument is ignored if DB user specified by ``bsimServerInfo``.
        """

    @typing.overload
    def __init__(self, bsimServerInfo: ghidra.features.bsim.query.BSimServerInfo):
        """
        Constructor
        
        :param ghidra.features.bsim.query.BSimServerInfo bsimServerInfo: the BSim database server info.  May be ``null`` if use limited to
        signature and update generation only (based upon configuration template).  If specified, 
        this object will convey the connecting user name.
        """

    def close(self):
        """
        This will be automatically invoked when BulkSignatures is out of scope, if using
        try-with-resources to create it. When this happens we need to clean up the 
        connection.
        """

    def createDatabase(self, configTemplate: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], trackCall: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new BSim database with a given set of properties.
        
        :param java.lang.String or str configTemplate: the type of database to create
        :param java.lang.String or str name: the name of the database
        :param java.lang.String or str owner: the owner of the database
        :param java.lang.String or str description: the database description
        :param jpype.JBoolean or bool trackCall: if true, the database should track callgraph information
        :raises IOException: if there's an error building the :obj:`BSimClientFactory`
        """

    def deleteExecutable(self, md5: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Deletes a specified executable from the database.
        
        :param java.lang.String or str md5: the MD5 of the executable to delete
        :param java.lang.String or str name: the name of the executable to delete
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def dropIndex(self):
        """
        Drops the current BSim database index which can allow for faster signature ingest after
        which a :meth:`rebuildIndex() <.rebuildIndex>` may be performed.  Dropping the index may also be done to
        obtain more accurate results albeit at the cost of performance.
        
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def dumpSigs(self, resultFolder: jpype.protocol.SupportsPath, md5: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Exports information about a binary to a local folder in XML format.
        
        :param jpype.protocol.SupportsPath resultFolder: the folder where the results will be stored
        :param java.lang.String or str md5: the MD5 of the executables to export
        :param java.lang.String or str name: the name of the executables to export
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def getCount(self, md5Filter: typing.Union[java.lang.String, str], exeNameFilter: typing.Union[java.lang.String, str], archFilter: typing.Union[java.lang.String, str], compilerFilter: typing.Union[java.lang.String, str], incFakes: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Retrieves the number of records in the database that match the filter criteria.
        
        :param java.lang.String or str md5Filter: the MD5 value must contain this
        :param java.lang.String or str exeNameFilter: the executable name must contain this
        :param java.lang.String or str archFilter: the architecture type must match this
        :param java.lang.String or str compilerFilter: the compiler type must match this
        :param jpype.JBoolean or bool incFakes: if true, include executables with an MD5 that we created
        :return: the number of executables matching the filter criteria
        :rtype: int
        :raises IOException: if there's a problem establishing the database connection
        """

    def installCategory(self, categoryName: typing.Union[java.lang.String, str], isDate: typing.Union[jpype.JBoolean, bool]):
        """
        Performs the work of installing a new category name. This will build the query
        object, establish the database connection, and perform the query.
        
        :param java.lang.String or str categoryName: the category name to insert
        :param jpype.JBoolean or bool isDate: true if this is a date category
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def installTags(self, tagName: typing.Union[java.lang.String, str]):
        """
        Performs the work of inserting a new function tag name into the database. This 
        will build the query object, establish the database connection, and perform the query.
        
        :param java.lang.String or str tagName: the tag name to insert
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def prewarm(self):
        """
        Performs a prewarm command on the BSim database.
        
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def rebuildIndex(self):
        """
        Rebuilds the current BSim database index.
        
        :raises IOException: if there's an error establishing the database connection
        :raises LSHException: if there's an error issuing the query
        """

    def signatureRepo(self, ghidraURL: java.net.URL, sigsLocation: typing.Union[java.lang.String, str], overwrite: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Adds function signatures from the specified project to the BSim database
        
        :param java.net.URL ghidraURL: ghidra repository from which to pull files for signature generation
        :param java.lang.String or str sigsLocation: the location where signature files will be stored
        :param jpype.JBoolean or bool overwrite: if true, overwrites any existing signatures
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises java.lang.Exception: if there's an error during the operation
        :raises CancelledException: if processing is cancelled
        """

    def updateRepoSignatures(self, ghidraURL: java.net.URL, sigsLocation: typing.Union[java.lang.String, str], overwrite: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Updates function signatures from the specified project to the BSim database
        
        :param java.net.URL ghidraURL: ghidra repository from which to pull files for signature generation
        :param java.lang.String or str sigsLocation: the location where update XML files are
        :param jpype.JBoolean or bool overwrite: if true, overwrites any existing signatures
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises java.lang.Exception: if there's an error during the operation
        :raises CancelledException: if processing is cancelled
        """



__all__ = ["HeadlessBSimApplicationConfiguration", "IterateRepository", "BSimLaunchable", "BulkSignatures"]
