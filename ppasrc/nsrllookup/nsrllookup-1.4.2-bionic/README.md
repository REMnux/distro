# nsrllookup

## What is it?
It's a command-line tool that allows you to quickly and efficiently triage files by MD5 hashes.

## Why would I want to do that?
Digital forensics has a big problem with needles and haystacks.  `nsrllookup` can significantly reduce the hay, thus making it easier to find needles.

## Can I get a prebuilt x64 Windows binary for it?
[Sure.](https://github.com/rjhansen/nsrllookup/releases/download/1.4.2/nsrllookup-1.4.2-win64.zip)

## How does it work?
The National Institute of Standards and Technology (NIST) maintains the National Software Reference Library (NSRL).  The NSRL is a library of every major piece of software released in the world dating back more than twenty years.

NIST also publishes MD5 hashes of every file in the NSRL.  This is called the Reference Data Set (RDS).

When looking at an unknown file, a good place to begin is to compute its MD5 hash and compare it against the RDS.  If the hash value is found in the RDS, your file is probably boring.  (At the very least, it's commonplace enough to have an RDS entry.)  This means your file is probably hay and not a needle.

## No, I mean, _how does it work?_
Oh!  Usage.  Sure, that.

Say you're using [md5deep](https://github.com/jessek/hashdeep/) to compute the hashes of a large collection of files.  To get a list of files that do _not_ match the RDS, you could do the following:

```
md5deep -r /path/to/collection > all_hashes.txt
nsrllookup < all_hashes.txt > rds_misses.txt
```

This would produce two files: `all_hashes.txt` containing the names of all files and their hashes, and `rds_misses.txt` containing the hash values of those files which did not appear in the NSRL RDS.

## The hash server
`nsrllookup` depends on the existence of a properly configured lookup server.  I maintain one at `nsrllookup.com`, and `nsrllookup` is configured by default to use it.  _If you're doing high volume lookups, please set up your own local server._

## How do I build it?
You'll need:

* [cmake](http://www.cmake.org)
    - Windows: 3.15 or later
    - UNIX: 3.05 or later
* A conforming C++14 compiler.  Compilers known to work well include:
    - Visual Studio 2017
    - Visual Studio 2019
    - GCC 5.0 or later
    - Clang 3.4 or later
* [boost](http://www.boost.org) 1.65 or later.  Windows users can get precompiled binaries from [Sourceforge](https://sourceforge.net/projects/boost/files/boost-binaries/), but see below.

### Windows
1. Begin by editing the CMakeLists.txt file.**  Open it in a text editor and follow the instructions in it.  You'll need to change the CMake version check to require 3.15, and comment out three lines of code immediately beneath it.  It's not hard.
2. Next: be careful to get the correct compiler and architecture for Boost.  Visual Studio 2017's internal version number is "14.1", and 2019's is "14.2".  So, for instance, if you want to download the binaries built for Visual Studio 2019 on x64, you'd download something like `boost_1_71_0-msvc-14.2-64.exe`.
3. Once you have Boost installed, open a Visual Studio development console.  Visual Studio offers two of them, one for 32-bit and one for 64-bit, so make sure to open the correct one.  `cd` into wherever you uncompressed `nsrllookup` and do this dance:

   1. **To build within the Visual Studio IDE:** `"\path\to\cmake.exe" . -DBOOST_ROOT=\path\to\Boost` will create a Visual Studio solution file, `nsrllookup.sln`.  Double-click on that to open `nsrllookup` in Visual Studio, where you can hack on it to your heart's content.
   2. **To build at the command-line:** `"\path\to\cmake.exe" . -DBOOST_ROOT=\path\to\Boost -G "NMake Makefiles"` and then `nmake`.

### UNIX and OS X
It should be a simple process.

```
cmake .
make
sudo make install
```

## Documentation
Full documentation is found in the manpage.  Once you've done the `make install` dance, `man nsrllookup` (UNIX only) will give you the rundown.  On all platforms, though, `nsrllookup --help` should be enough to get you going.

## Licensing
ISC.  Share and enjoy.