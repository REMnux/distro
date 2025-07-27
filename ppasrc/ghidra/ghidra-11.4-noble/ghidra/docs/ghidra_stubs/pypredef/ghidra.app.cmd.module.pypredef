from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.program.model.block
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class ComplexityDepthModularizationCmd(AbstractModularizationCmd):
    """
    This command will organize a program tree into levels from the bottom up.  In other words, all
    the leaf functions are at the same level and all the functions that only call leaf functions are
    one level less and so on and so forth.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: ghidra.program.util.GroupPath, treeName: typing.Union[java.lang.String, str], selection: ghidra.program.util.ProgramSelection, blockModel: ghidra.program.model.block.CodeBlockModel):
        ...


class AbstractModularizationCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], path: ghidra.program.util.GroupPath, treeName: typing.Union[java.lang.String, str], selection: ghidra.program.util.ProgramSelection, blockModel: ghidra.program.model.block.CodeBlockModel):
        ...


class CreateDefaultTreeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create a root in the program; the root module has
    fragments named the same as the memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str]):
        """
        Constructor for CreateDefaultTreeCmd.
        
        :param java.lang.String or str treeName: name of the tree to create
        """


class CreateFolderCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create a folder in a program tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], parentName: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str treeName: name of the tree where the new Module will reside
        :param java.lang.String or str name: of the new Module
        :param java.lang.String or str parentName: name of the parent module
        """


class DeleteTreeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Delete a tree in the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str]):
        """
        Constructor for DeleteTreeCmd.
        
        :param java.lang.String or str treeName: name of tree to delete
        """


class ReorderModuleCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to reorder children in a module.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], parentModuleName: typing.Union[java.lang.String, str], childName: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]):
        """
        Constructor for ReorderModuleCmd.
        
        :param java.lang.String or str treeName: tree that contains the parent module identified by
        the parentModuleName
        :param java.lang.String or str parentModuleName: name of the module with the children to reorder
        :param java.lang.String or str childName: name of the child to move to the new index
        :param jpype.JInt or int index: new index for the child
        """


class DominanceModularizationCmd(AbstractModularizationCmd):
    """
    this code will apply the Dominance algorithm to a module or fragment in
    a program tree.  First the code generates a call graph and from there a
    dominance graph and finally a dominance structure in the program tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: ghidra.program.util.GroupPath, treeName: typing.Union[java.lang.String, str], selection: ghidra.program.util.ProgramSelection, blockModel: ghidra.program.model.block.CodeBlockModel):
        ...


class RenameTreeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to rename a tree in a program; this does not affect
    the root module of the tree.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Constructor for RenameTreeCmd.
        
        :param java.lang.String or str oldName: old name of the tree
        :param java.lang.String or str newName: new name of the tree
        """


class CreateFragmentCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create a Fragment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], parentName: typing.Union[java.lang.String, str]):
        """
        Construct a new CreateFragmentCmd.
        
        :param java.lang.String or str treeName: name of the tree where the fragment will reside
        :param java.lang.String or str name: name of the new Fragment
        :param java.lang.String or str parentName: name of the module that is the parent of the fragment
        """

    def applyTo(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Apply the command; if the name already exists, then the fragment 
        will not be created.
        
        :return: false if the fragment was not created
        :rtype: bool
        
        .. seealso::
        
            | :obj:`ghidra.framework.cmd.Command.applyTo(ghidra.framework.model.DomainObject)`
        """


class MergeFolderCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to merge a Folder with its Parent folder. Immediate children of
    the folder are moved to its parent.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, treeName: typing.Union[java.lang.String, str], folderName: typing.Union[java.lang.String, str], parentName: typing.Union[java.lang.String, str]):
        """
        Construct a new command.
        
        :param java.lang.String or str treeName: name of the tree that this command affects
        :param java.lang.String or str folderName: name of the folder (module) that is being merged in
        with its parent
        :param java.lang.String or str parentName: name of the parent that will end up with children of
        the folder named folderName
        """


class RenameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for renaming a fragment or a module in listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, treeName: typing.Union[java.lang.String, str], isModule: typing.Union[jpype.JBoolean, bool], oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], ignoreDuplicateName: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new RenameCmd.
        
        :param java.lang.String or str treeName: name of the tree where the module or fragment resides
        :param jpype.JBoolean or bool isModule: true if a module is to be renamed
        :param java.lang.String or str oldName: current name of the module or fragment
        :param java.lang.String or str newName: new name for the module or fragment
        :param jpype.JBoolean or bool ignoreDuplicateName: true means to ignore the exception and
        don't do anything
        """

    @typing.overload
    def __init__(self, treeName: typing.Union[java.lang.String, str], isModule: typing.Union[jpype.JBoolean, bool], oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Construct a new RenameCmd.
        
        :param java.lang.String or str treeName: name of the tree where the module or fragment resides
        :param jpype.JBoolean or bool isModule: true if a module is to be renamed
        :param java.lang.String or str oldName: current name of the module or fragment
        :param java.lang.String or str newName: new name for the module or fragment
        """


class SubroutineModelCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command that organizes a Module or Fragment according to a specified block
    model. This organization produces a "flat" (single layer) partitioning.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.CodeBlockModel`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, groupPath: ghidra.program.util.GroupPath, treeName: typing.Union[java.lang.String, str], blockModelService: ghidra.app.services.BlockModelService, modelName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.util.GroupPath groupPath: group path of the affected Module or Fragment
        :param java.lang.String or str treeName: name of the tree where group exists
        :param ghidra.app.services.BlockModelService blockModelService: service that has the known block models
        :param java.lang.String or str modelName: name of the model to use
        """

    def setPluginTool(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ModuleAlgorithmCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command that applies the "module" algorithm to a specified Module or
    Fragment. 
    Gets an iterator over the code blocks containing the selected folder or fragment.
    Creates a folder for each code block in the iterator.
    For each code block, gets an iterator over code blocks containing the code block.
    For each of these code blocks, create a fragment and move the code units to the fragment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: ghidra.program.util.GroupPath, treeName: typing.Union[java.lang.String, str], blockModelService: ghidra.app.services.BlockModelService, partitioningModelName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.util.GroupPath path: path the source module or fragment where the algorithm
        will be applied
        :param java.lang.String or str treeName: name of the tree
        :param ghidra.app.services.BlockModelService blockModelService: service that has the known block models
        :param java.lang.String or str partitioningModelName: name of the model to use
        """

    def setPluginTool(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ComplexityDepthModularizationCmd", "AbstractModularizationCmd", "CreateDefaultTreeCmd", "CreateFolderCommand", "DeleteTreeCmd", "ReorderModuleCmd", "DominanceModularizationCmd", "RenameTreeCmd", "CreateFragmentCmd", "MergeFolderCmd", "RenameCmd", "SubroutineModelCmd", "ModuleAlgorithmCmd"]
