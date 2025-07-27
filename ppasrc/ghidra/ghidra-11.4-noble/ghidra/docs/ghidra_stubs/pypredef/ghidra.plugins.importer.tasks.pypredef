from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.framework.model
import ghidra.plugins.importer.batch
import ghidra.util.task


class ImportBatchTask(ghidra.util.task.Task):
    """
    Performs a batch import using the data provided in the :obj:`BatchInfo` object which
    specifies what files and the import language that should be used.
     
    
    If there are just a few files to import, they will be opened using the ProgramManager,
    otherwise the programManager parameter will be unused.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_PROGRAMS_TO_OPEN: typing.Final = 50

    def __init__(self, batchInfo: ghidra.plugins.importer.batch.BatchInfo, destFolder: ghidra.framework.model.DomainFolder, programManager: ghidra.app.services.ProgramManager, stripLeading: typing.Union[jpype.JBoolean, bool], stripAllContainerPath: typing.Union[jpype.JBoolean, bool]):
        """
        Start a Batch Import session with an already populated :obj:`BatchInfo`
        instance.
        
        :param ghidra.plugins.importer.batch.BatchInfo batchInfo: :obj:`BatchInfo` state object
        :param ghidra.framework.model.DomainFolder destFolder: :obj:`DomainFolder` where to place imported files
        :param ghidra.app.services.ProgramManager programManager: :obj:`ProgramManager` to use when opening newly imported files, null ok
        :param jpype.JBoolean or bool stripLeading: boolean true if each import source's leading path should be omitted
        when creating the destination project folder path.
        :param jpype.JBoolean or bool stripAllContainerPath: boolean true if each imported file's parent container
        source path should be completely omitted when creating the destination project folder path.
        (the imported file's path within its container is still used)
        """



__all__ = ["ImportBatchTask"]
