import os, sys, re
import string
import optparse
import shutil

import vcproj_tmpl

TOP_DIR = 'cybozulib'
BACKUP_SUF = '.old'
THIS_PATH = os.path.abspath(__file__)

INCLUDE_DIR = [
# move to common.vcprops
]

LIB_DIR = [
	r'lib'
]

# get relative path to top dir from here

def getPathToTop(path, topDir):
	list = path.split("\\")
	dir = topDir if topDir else TOP_DIR
	try:
		p = list.index(dir)
		return "..\\" * (len(list) - p - 1)
	except:
		print "not found topdir:" + dir
		exit(1)

def makeGUID(projName):
	try:
		f = open(projName, 'r')
		p = re.compile(r'.*ProjectGUID="(\{.*?\})"')
		for line in f:
			s = p.split(line)
			if (len(s) > 1):
				return s[1]
		print "bad format:" + projName
		exit(1)
	except:
		import uuid
		return '{' + str(uuid.uuid4()).upper() + '}'

def makeSourceList(src):
	return string.join('<File RelativePath="' + s + '"></File>' for s in src)

def makeList(inc, relTop):
	return string.join((relTop + '../cybozulib/' + i for i in inc), ';')

def getSlnGuid(slnData):
	for line in slnData:
		p = re.search(r'Project\("(\{.*?\})"\)', line)
		if p:
			return p.group(1)

def getLibGuid(lib, slnData):
	for line in slnData:
		p = re.search(r'Project\(.*?\) = "' + lib + '",.*(\{.*?\})"', line)
		if p:
			return p.group(1)

def appendProjToSln(sln, targetName, projGuid, lib):
	projPath = os.getcwd().split(TOP_DIR + '\\')[1] + '\\' + targetName + '.vcproj'
	backup = sln + BACKUP_SUF

#	if not os.path.exists(backup):
	shutil.copy(sln, backup)

	fi = open(backup, "rb")
	slnData = [line for line in fi]

	cybozulibGuid = getSlnGuid(slnData)


	libGuid = [getLibGuid(name, slnData) for name in lib]

	# append top
	pos = 2
	slnData.insert(pos, r'Project(' + cybozulibGuid + r'") = "' + targetName + r'", "' + projPath + r'", "' + projGuid + '"\r\n')
	pos = pos + 1
	if len(libGuid) > 0:
		slnData.insert(pos, '\tProjectSection(ProjectDependencies) = postProject\r\n')
		pos = pos + 1
		for guid in libGuid:
			slnData.insert(pos, guid + r' = ' + guid + '\r\n')
			pos = pos + 1
		slnData.insert(pos, '\tEndProjectSection\nEndProject\r\n')

	pos = slnData.index('\tGlobalSection(ProjectConfigurationPlatforms) = postSolution\r\n')
	pos = pos + 1

	list = ['Debug|Win32.ActiveCfg = Debug|Win32',
			'Debug|Win32.Build.0 = Debug|Win32',
			'Debug|x64.ActiveCfg = Debug|Win32',
			'Debug|x64.Build.0 = Debug|Win32',
			'Release|Win32.ActiveCfg = Release|Win32',
			'Release|Win32.Build.0 = Release|Win32',
			'Release|x64.ActiveCfg = Release|Win32',
			'Release|x64.Build.0 = Release|Win32']
	for t in list:
		slnData.insert(pos, '\t\t' + projGuid + r'.' + t + '\r\n')
		pos = pos + 1

	fo = open(sln, "wb")
	for line in slnData:
		fo.write(line)

def createProj(target, src, topDir, outDir):
	targetName, targetSuf = os.path.splitext(target)
	if (not targetSuf in [".exe", ".lib"]):
		print "target must be exe or lib"
		exit(1)
	projName = targetName + '.vcproj'
	projGuid = makeGUID(projName)

	relTop = getPathToTop(os.getcwd(), topDir)

	class MyTemplate(string.Template):
		delimiter = '@'

	tmpl = MyTemplate(vcproj_tmpl.tmpl)

	outputBase  = relTop + '../' + outDir + '/' + ("bin\\" if targetSuf == '.exe' else "lib\\") + targetName

	definition = '_LIB' if targetSuf == '.lib' else ''

	proj = tmpl.substitute({
		'PROJECT_GUID' : projGuid,
		'ROOT_NAMESPACE' : targetName,
		'CONFIGURATION_TYPE' : '1' if targetSuf == '.exe' else '4',
		'INHERITED_PROPERTY_SHEETS'   : makeList(['common.vsprops', 'release.vsprops'], relTop),
		'INHERITED_PROPERTY_SHEETS_D' : makeList(['common.vsprops', 'debug.vsprops'], relTop),
		'ADDITIONAL_INCLUDE_DIRECTORIES' : makeList(INCLUDE_DIR, relTop),
		'ADDITIONAL_LIBRARY_DERECTORIES' : makeList(LIB_DIR, relTop),
		'PREPROCESSOR_DEFINITIONS' : definition,
		'PREPROCESSOR_DEFINITIONS_D' : definition,
		'OUTPUT_FILE' : outputBase + targetSuf,
		'OUTPUT_FILE_D' : outputBase + 'd' + targetSuf,
		'SOURCE_FILE' : makeSourceList(src)
	})

	f = open(projName, 'wb')
	f.write(proj)
	f.close()

"""
ex.
test\src>python ..\..\cybozulib\tool\create_vcproj.py test.exe test.cpp -d test -o ..\..\cybozulib
"""
def main():
	parser = optparse.OptionParser(usage = 'usage: %prog [-d top dir] [-o outdir] prog.exe file1.cpp file2.cpp ...')
	parser.add_option('-d', '--dir', help = 'top directory', dest = 'dir')
	parser.add_option('-o', '--out', help = 'out directory', dest = 'out')

	(options, args) = parser.parse_args()

	topDir = ""
	if options.dir:
		dirs = options.dir.split(',')
		if len(dirs) > 0:
			topDir = dirs[-1]

	outDir = "cybozulib"
	if options.out:
		dirs = options.out.split(',')
		if len(dirs) > 0:
			outDir = dirs[-1]

	if len(args) == 0:
		parser.error('need progname')
		exit(1)

	target = args[0]
	src = args[1::]

	print 'target:' + target
	print 'src:' + str(src)
	print 'dir:' + topDir
	print 'outdir:' + outDir

	createProj(target, src, topDir, outDir)

if __name__ == '__main__':
	main()
