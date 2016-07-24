GCFOS – Open Source File Deduplication Service and Deduplicated Block Store
===========================================================================

**Summary**: Provides an open-source (covered by AGPLv3 license)
client/server system for common-file deduplication and a redundant
high-availability compressed block-level storage system with automatic
“online” block deduplication. Extensive caching capability is integrated
into both the client and server components to dramatically improve
performance (100-150 MB/sec throughput is achievable to the block store
when local caching is enabled).

**History**: The moniker “GCFOS” comes from “Global Common-File Object
Store” since at inception it was envisioned that the system would only
provide the capability to eliminate common-files that were discovered
across multiple clients’ (of UltraBac) computers. The “object store”
part of the name came from the intention to use an AWS S3 object store
to efficiently store common files.

**Platforms supported**: The server component is designed to run on an
x64 Windows Platform (tested on Windows Server 2008 and 2012). The
client can be compiled for x86 and x64 Windows and Linux platforms
(tested on most Windows clients and RedHat 6). There is also a .Net
client for C\# and other .Net languages. The clients are designed to
have minimal dependencies on 3rd-party libraries, and can be built very
lightweight for limited-resource applications.

**Dependencies:**

The software requires the following components.

**Microsoft Visual Studio 2015** for compiling all modules (with the
exception of the Linux client for which **‘gcc’** is used)

**LMDB**: Lightning memory database. This is an essential component of
the server module, and also utilized by the client (optionally) to
greatly improve performance (via caching). Covered by OpenLDAP public
license.

**BTree**: <https://github.com/google/btree> Covered by Apache License
v2

**Intel IPP**: Commercial license, but free for development and
royalty-free usage. Provides high-performance compression, hash
computation and cryptographic functions:
<https://software.intel.com/en-us/articles/free-ipp>

**Wix**: Used for installation. Covered by MS-RL:
<http://wixtoolset.org/about/license/>

Functionality
=============

There are two distinct modes in which the server can run and is
controlled by two distinct executable binaries that can be produced.
This means that the mode the server is not controlled by a configuration
setting at runtime but rather which EXE file is deployed on the server.
The EXE created is controlled by the definition of a macro called
**ULTRABAC\_CLOUD\_USE** which is not defined in the default project
configurations, but is defined in the UB\_Debug/UB\_Release project
configurations of the server project. For want of a better term, the
default project configuration will be referred to as a “Local mode” and
when the macro is defined the configuration will be referred to as a
“Global mode”. The client software is consistent across both modes of
operation, so can be coded identically – API calls are provided to
detect whether the file store or block stores are available at runtime.
The differences between behaviors of the two modes are outlined below.

Local Mode
----------

-   This mode is designed for the server to run on a secure local
    network, or over a secure VPN where the server is hosted in the
    cloud

-   If the clients are all on the same IP subnet, then the clients can
    auto-discover/configure themselves without any manual configuration
    necessary (auto-configuration is possible on different subnets but
    will require a GCFOS server to run on each subnet in
    “redirection mode”)

-   Either the file-deduplication feature can be enabled, or the “block
    store” feature can be enabled or both can be enabled.

-   Authentication for client is simple and automatic – clients
    identify/configure themselves to the server based on their
    computer name.

-   No verification is performed to determine whether any client has
    “rights” to retrieve files resident on server.

Global Mode
-----------

-   This mode is designed for cloud or backup providers to offer
    deduplication server PaaS (Platform as a service) to their clients
    with their own backup products incorporating the necessary client
    integration

-   This configuration is designed to run on a computer
    (typically cloud-hosted) exposed to the internet (IANA assigned TCP
    port 1910 must be allowed in).

-   Only file-deduplication is enabled, the “block store” is not
    available (though it would be rather trivial to enable block store
    operations if necessary)

-   Each organization that wishes to perform file-deduplication is
    assigned a unique client-id\# and ALL computers in that organization
    must use the **same** credentials to connect to the server. This is
    critical to note: proprietary/confidential files would never be
    identified as common and uploaded to the server because no more than
    one organization would suggest their hashes. If however, a
    sufficient number of related organizations were all given different
    client credentials it then becomes possible that files that are
    common amongst their computers will be identified as common and
    uploaded to the server.

-   Authentication is necessary – a 32byte shared-secret must be
    configured on each client computer attempting connection

-   Client computers can be manually configured by using registry
    entries, or a local GCFOS server can be running in “redirection”
    mode that allows each client computer to receive their credentials
    from a server on their local network

-   The idea with the global configuration is to build a system that
    recognizes common files across many organizations’ computers but
    never shares data of files that are unique to any organization
    (other than a cryptographically-secure hash).

-   Because the server may be exposed to the public internet, some
    hardening against malevolent actors is built-in (e.g. a
    DDoS attack). Any unexpected communication data or a failed
    authentication attempt results in that IP address being placed in a
    “banned” IP address database and no communication is possible with
    that IP address until a configurable period of time has elapsed.
    Currently the timeout period is short for testing purposes, but in
    real-world deployments should be set to 10 minutes or more.

-   The server verifies each request to retrieve a common-file by
    providing a unique-to-client verification key at the time of query.
    This prevents retrieval by any client that has not previously
    encountered the full file at some point. This adds 4-bytes that a
    backup application must store along with other metadata about
    the file.

Method of Operation (from Client Perspective)
=============================================

Although not completely current, please review the Visio files for
reference:

.\\GENSHA1\\Flowcharts.vsd

.\\GENSHA1\\DataModel.vsd

Review the GENSHA1 \\ Linux\_GENSHA1 project as the primary references
as this command-line project exposes virtually all functionality of the
client library. For example, the command to check whether any files are
common in the C:\\Windows\\System32 directory would be:

GENSHA1.exe -l –p c:\\Windows\\System32

The application must first establish a connection to a GCFOS server.
This is achieved by instantiating a variable from GCFOS\_Client(), then
calling the methods Connect() then Auth(). If either of these methods
fail then the variable should be released and an error reported. The
library cannot be used in this case.

Note that there is serialization present in an instance of a
GCFOS\_Client() variable. This means that several threads could
concurrently share one instance of the client, but this is not
recommended as any concurrent access that requires both threads to
communicate with the server will result in one (or more) threads
blocking until the server communication is complete. For multiple
concurrent access to the server, simply instantiate multiple
GCFOS\_Client objects as necessary.

File Deduplication
==================

1\. The application should check to see that the server has a valid
file-store configured by calling FileStoreEnabled()

2\. The hash and filesize of each file needs to be calculated by calling
GetHash() or GetHashForHandle() if the file has already been opened, a
handle is available and the filesize/last-write time are known. The
client library will search its local (optional) cache to see if the hash
is already known for this file (and it has not been subsequently
modified).

3\. Call Query() on the hash/filesize pair. Note that the Unique/Resident
statuses are optionally cached by the client and therefore do not
involve any communication with the server. The calling application acts
according to response of Query():

-   GCFOS\_SRV\_RESP\_WANTED: This file needs to be “donated” (uploaded
    to server), so call ContributeFile() to do so (this may be done in a
    separate thread with its own GCFOS\_Client() instance if so desired)

-   GCFOS\_SRV\_RESP\_RESIDENT: This file is known and already present
    on the server’s stores. If this file ever needs to be retrieved in
    the future, all that will be needed is the SHA1 hash(20 bytes),
    filesize(4 bytes) and verification key(4 bytes). Note that the
    verification key is only necessary when connected to a GCFOS server
    using Global Mode.

-   GCFOS\_SRV\_RESP\_UNIQUE: This file is known to be a “unique” file
    to this client (will no longer be considered as a candidate for a
    common file). In a backup application this means that this file’s
    data will need to be backed up normally.

-   GCFOS\_SRV\_RESP\_LIMBO: The server has not yet determined whether
    this file is unique to the client or possibly a common-file. In a
    backup application this means that this file should be backed
    up normally.

4\. Repeat steps 2 and 3 for any other files in question.

Block Store
===========

1\. The application should check whether the server is configured with a
valid block store by calling BlockStoreEnabled()

2\. To store all of the file data in the block store for a given file,
call GetHashDataLengthForFileSize() to get the size of the data area
needed to store the hash-chain to represent the entire file. The block
size used is fixed to 0x1000 (GCFOS\_BLOCK\_SIZE) and any (remainder)
block that is smaller than 0x100 (GCFOS\_MINIMUM\_BLOCK\_SIZE) is copied
in its entirety, and blocks between 0x200 and 0xfff are zero-byte padded
to fill 0x1000. Each block is represented by a 28-byte hash, so a 1GB
file will be represented by 7MB of hash-chain data. This buffer must be
allocated by the calling application, and the block-chain can be
obtained by calling GetBlockHashesForFile(). Alternatively, the data
blocks can be forced into the block store for a given file by calling
SendDataBlocksToGCFOS(), but if there’s a remainder block smaller than
0x100 (GCFOS\_MINIMUM\_BLOCK\_SIZE) it will be discarded.

3\. To store a memory buffer of data in the block store directly, call
StoreBlocks() which will convert that memory buffer into hashes. To
retrieve that data later (convert from hashes), call RetrieveBlocks().
Note that the maximum number of blocks that may be stored or retrieved
may not exceed GCFOS\_BLOCKS\_PER\_QUERY (16) which means that the
buffer size may not exceed 64KB.

4\. Note that the client has two levels of local caching when using the
block store, determined when calling Connect() by the parameters
*EnableLocalBlockCache* and *EnableExtendedBlockCache*. When the local
block cache is enabled, the client maintains a local database to allow
it to know when the server has already stored a given block. The
Extended cache allows the retrieval of the complete hash chain for any
file already stored in the block store by GetBlockHashesForFile() . This
means that to “backup” (convert a file to hashes) an entire file that is
already stored in the block store can be achieved in typically 50us to
1.0ms. The performance increase of these cache options can increase
throughput 50 to 200 times. The cost in disk space for these cache
options is approximately 1% (each) of the size of the data stored in the
block store. For example, if the client has stored 1TB of data in the
block store and extended caching has been enabled, the client’s local
cache database will occupy at least 2GB of local disk space.

Details of Implementation
=========================

GCFOS\_Server
=============

This is the core module that responds to client requests. The Wix
installation package will install this module as an auto-start service
so that the service is always available but this makes its UI
inaccessible. For development it is best to run it as an executable
which provides a primitive UI – displaying logging information and a
limited keyboard interface (press ‘?’ to show commands).

The C\# sub-project ConfigureDeduplicationServer provides a UI for
configuring the server’s operation. Review the documentation at location
below for more information:

*.\\GCFOS\_Server\\ConfigureDeduplicationServer\\Configuring UltraBac
Deduplication Server.docx*

The server needs to be configured with at least one primary repository
and an optional secondary repository. The repositories can utilize a
local/remote path using normal file-systems (appropriate for smaller
repositories of less than 1M expected common files), or cloud-based
repositories utilizing AWS S3, Azure Blob Storage or OpenStack
CloudFiles. If using a cloud provider for object storage, placing the
GCFOS server on a virtual machine on that same cloud provider (e.g. EC2
when using S3) can improve performance and reduce data-transfer costs
that may be levied by the cloud provider.

The server maintains several database tables in LMDB which is a
memory-mapped database that offers very high-performance NoSQL
semantics. All tables are stored within the .\\gcfosdb sub-directory
from the main executable directory. This is automatically created at
startup, and the initial size is defined by the
ConfigureDeduplicationServer.exe program. For file deduplication only,
an initial size of 16GB is probably sufficient for typical usage of
around \~100 clients. If the block store is enabled, then this size
should be set to 1.5% of the size of the expected amount of data to be
stored in the block store. Although the database can be expanded
on-the-fly, this requires that all operations are temporarily suspended
for the resize operation and can cause a significant delay whilst the
resize operation is processed, so it is recommended to set the initial
database size appropriately prior to first run.

If the server is configured for block-store, then a local path (can be a
UNC path if preferred) must be configured to store all of the block
data. This data is compressed as it is received and stored in
monotonically increasing subdirectory/file structure to reduce overhead
of file-system and improve performance. Each file is written to
sequentially and allowed to grow to approximately 256MB until the file
is closed and the next sequential file sequence number is begun.
Optionally, these files may be additionally stored on a cloud-provider’s
object store (eg. S3). The primary disk path is always used for
retrieval – in the event that the file is not present during a
RetrieveBlocks() request, then the entire block-file(s) needed will be
retrieved first from the cloud provider and placed in the correct
location in the primary disk path location. This design means the
primary disk path location, if a secondary exists, can be thought of as
a local cache and old block-files can be deleted if the primary disk
path is running out of space.

Embedded in .\\gcfosfb\\gcfosdb.dat database file are the following
tables and their uses:

**limbo/limbo2**: a list of all hash/size pairs and client-ids /
when-added times. These are all the files that are being considered for
future inclusion as a common-file

**resident**: a list of hash/size pairs of files that have been
successfully stored in the repository

**wanted**: a list of hash/size pairs of files that have reached a
configurable threshold of instances in limbo so that the server now
wishes to store a copy of the file in its repository. Once a hash/size
pair makes it to ‘wanted’ all instances are deleted from ‘limbo’.

**clientdb/clientdb2**: A list of all the client ids that this server
has registered. For “local mode” use, this is merely a simple
computer-name to id translation table. When the server is compiled for
“global mode” then this stores the randomly-generated 32-byte
shared-secret keys for each client used to perform the
challenge-response encrypted authentication.

**banned**: only used on “global mode” configurations, this table
contains a list of IP addresses that must be ignored (and a time when
their “timeout” comes to an end).

**blocks**: this provides the ability to query whether a block has been
stored previously, and if so the file sequence\#/offset where the data
resides.

**sessions**: stores information (for reporting) about statistics for
each connection made to the server

**update**: a transient table used to signal to a background thread when
to process particular entries in the limbo table to determine if they
meet the threshold requirements. This is so that client Query()
operations can be processed quickly without the overhead of checking
through limbo records.

File store design
=================

I chose an SHA1 hash (160 bit) for the primary hash to recognize
identical files, and I decided to augment that with the 32bit file size.
In retrospect this does not offer a full 32bits of Shannon entropy
because file-size is not evenly distributed, but I estimate that there
are still at least 10 bits of entropy, resulting in a total of 170bits.
The objects used to represent the file’s data are named:

&lt;file-hash-in-hex&gt;-&lt;filesize in hex&gt;/zzzc

E.g.:

931a8bcede83e83e65101920100a4124aec1f297-14800000/0f1c

Where ‘c’ is a character that represents whether this particular block
is compressed or not(c/n) and ‘zzz’ represents the upper part of the
file offset for this block of data i.e. 0xzzz00000. This means that each
file represents at most 1MB of the file data, and there can be at most
4,096 objects for any one file (the maximum file size for deduplication
detection is 4GB). It was designed this way to reduce data-transfer for
operations where only part of a file is requested to be retrieved,
implemented by function RetrieveFilePortion().

A consideration whenever using hashes to distinctly recognize discrete
data sequences like files is the possibility of the same hash being used
to identify two different files, known as a “hash collision”. A good
discussion of this topic and the underlying “birthday problem” is
located here:

<http://preshing.com/20110504/hash-collision-probabilities/>

The simplified calculation is that the probability of a collision is
approximated as: k\^2/2N where ‘k’ is the number of values (hashes in
this case) generated and ‘N’ is the total address space (different
possible hash values). So, given say 10,000,000 common-files detected by
the server, the probability that there is a collision in this case will
be 10,000,000 \^ 2 / 2 \* 2 \^ 170 which is \~ 3 x10\^-38 (the odds of a
meteor hitting your house are millions of times more likely).

Block store design
==================

Although the primary use-case for the design of block store was to store
file (or disk image) data, the store may be used as an efficient
compressed store for any unstructured data where there is a high
likelihood of data blocks that are identical. The block store will only
be useful in the case where data is consistently aligned on some
boundary and greater than 0x100 bytes, up to (ideally exactly) 0x1000
bytes (or multiples thereof) so that blocks containing the same data can
be detected. The typical use-case would be “image backup” where data
blocks are always aligned on sector boundaries (usually 0x200 or
0x1000), or the backup of traditional file data where contents remain
the same, without insertions/deletions causing the data to have
different new alignments. Data being written at the end of the data,
appending to existing data, is handled efficiently since only the new
blocks added will need to be stored.

The server tracks the “current” sequence\#/offset as it’s writing
sequentially to the current blocks file. The naming convention is
xxxxxx/yyyy so the relative path for the 1,234,567th file sequence will
be stored in the relative path 000123/4567. Once that file reaches
around 256MB it will be closed and the next sequence will be opened,
000123/4568. This naming convention ensures that a single sub-directory
contains no more than 10,000 files and so efficiently uses NTFS (or
other file system). Block data is written compressed into this file,
which means that the offset needs to be stored for each block reference
in the “blocks” database. Blocks are all 0x1000 bytes in size, and are
zero-filled as necessary (blocks must be at least 0x100 bytes in
length). The first two bytes at the offset indicated in the blocks file
provide the compressed length of this block. By storing the compressed
length in the block data itself, this means that the “blocks” database
could be reconstructed from the raw blocks data if that were ever
necessary.

All blocks use an SHA512/224 hash which occupies 28bytes per hash, and
provides a hash space of 2\^224. This is sufficient space to reduce a
hash collision to very safe levels. For example, if storing 1PB of data
in the block store, the probability of a hash collision is approximately
1.4x10\^-45.

When enabling both file-store and block-store on server
-------------------------------------------------------

If the block store is enabled and the server detects that a file is a
common file, there really is no need to duplicate the data in both
stores. In such a case, rather than using the naming convention detailed
in the “file store design” above, the “zzzc” component is replaced by
simply “h” representing “hashchain”. This is a tiny file (&lt;1% of
original file size) that represents all of the block-hashes of the file
needed to reconstruct the file from reads from the block store. If there
is a block of data at the end of the file that is less than 0x100 bytes,
then this “straggler block” is written directly to the end of the
hashchain object. Both whole-file and portion retrievals are supported
when hashchains are used to represent the common files. File portion
retrievals are very efficient since only the blocks requested by the
retrieval have to read (a 4KB granularity compared to 1MB when the
regular file store is used).

Important distinction between file-store and block store
--------------------------------------------------------

Only common files are stored in the file-store. In a typical backup
application then, if a Query() indicates that the file is not common,
the file data must be backed up using other methods. A block-store
though contains all data, whether it is common or not. It will only ever
store one copy of the same block that occurs multiple times
automatically. So, when using the block store to store a file, a backup
application need not store the file data for that file, all it would
need to store would be the metadata and all of the block hashes for that
file.

LCUD – Local Client Unique Database
===================================

Rather than burden the server’s primary LMDB database with tracking all
of the files that have been identified as non-common (unique to a
particular computer or client), this information is stored on the server
in a simple directory structure. Periodically the server will go through
its entire “limbo” database and if it finds entries there that are old
(e.g. 60 days, or other configurable value) it will transfer those limbo
entries to the corresponding LCUD file for that particular client. The
client will learn its LCUD and store/cache it locally and will then
never query the server again for that file. The rationale behind this
decision is that if commonality is not discovered for a given file
within a reasonable time frame, then it is very unlikely that this file
will ever be a common file and the server’s overhead can be reduced by
not querying it about these files in the future. The LCUD is implemented
using a “total” file, represented by the “0” file in the client’s LCUD
sub-directory which contains every entry, and then there are “delta”
files which just contain the entries new to that particular update. Each
client tracks the version that it has currently. So if the version that
the client has is at “4” and the server indicates that it is at “6”,
then the client will add to its local database only the server’s “5” and
“6” files. If the client did not have any LCUD information, then it
would request the “0” file and then it would be current at “6” because
that contains all delta files.

Blocks Purging Option
=====================

The server may be configured to enable blocks purging. At present this
means that the server will keep a last-referenced time for every block
stored in the block store in its “blocks” database. Therefore, in the
future it would be possible to build a program to perform some sort of
purging operation to remove block data from the database and block-store
for blocks that have not been referenced in a certain time period
(typically years). This adds rather a lot of overhead to maintain, and
thought has gone into the design to minimize the overhead yet still with
the goal to ensure that the aging info in the block database is accurate
to within certain tolerances. When the clients have a local block-cache
database, it becomes necessary to let the server know that these are
still being referenced. But doing so as-needed would render the whole
point of the cache worthless. The method to counter this is to perform a
random sampling of the local block cache with the server so that the
server may update the block database appropriately. This is done when
the client closes its session with the server. This may cause a delay of
several seconds since the entire local cache is processed sequentially.
This is handled in function UpdateLocalBlockCache() where approximately
3% of records are transferred to the server in any session. This design
is only effective if the client is used on a regular basis – if the
GCFOS client is only used infrequently then it would be safer to disable
the client’s local block cache rather than run the risk of the server
not learning that certain blocks of the client’s are still referenced.
Note that the client’s block cache also contains aging information so
that blocks not referenced in 45 days (hardcoded currently) are removed
from the cache.

Note about GCFOS\_Server and GCFOS\_Client designs
==================================================

The server is designed around a central state-machine leveraging I/O
Completion Ports (IOCP) which allows a low-overhead high-throughput
multi-threaded mechanism for handling the I/O performed through the TCP
sockets and local disk. Unfortunately, the design of Linux does not
really offer anything with identical semantics and would therefore make
porting the server to Linux more difficult, likely using an “epoll”
mechanism instead. This design almost completely eliminates the use of
synchronization objects, except for some shortly-held global variable
protection. The program initializes one thread per available CPU core
for processing connections.

The client was designed around simplicity and ease of implementation.
The only real complexity in the design is the use of multiple threads to
drive concurrent hash generation to significantly reduce the time needed
to calculate the hashes of multiple buffers. Because the client is
responsible for all hash calculations and compression operations, most
of the CPU is utilized by the clients, effectively making this a
highly-distributed design and drastically enhancing the scalability of
the server to be able to handle thousands of concurrent clients. The
IOCP ports being used to drive concurrent hash calculations are emulated
on Linux by using some native synchronization objects. The port is done
on the same source code, using macros where necessary to translate
Windows-only functions into their Linux equivalents. The only dependency
when building the Linux client is the LMDB library must be built on
Linux too. Both versions of the client can be built for 32 or 64 bit
platforms. Because of the memory-mapped nature of LMDB, the 32bit
clients cannot cache block entries.

Building the projects
=====================

The project requires Intel’s IPP “Integrated Performance Primitives”
which is a commercial package, but is available for free and with
royalty-free distribution. The code was built and tested with version
8.2.2 of IPP, but should run with later versions -- although some minor
modifications would be likely.

In order to start Visual Studio 2015 with the correct environment,
review the file setenv64.cmd (and setenv32.cmd for 32bit). Review the
file and make edits as necessary, then use it to start a Visual Studio
2015 session with the right environment for building the projects.

Location of Visual Studio 2015:
-------------------------------

cd /d "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC"

IPP Variables (example for 64bit)
---------------------------------

set IPP\_INCLUDE=C:\\Program Files (x86)\\Intel\\Composer XE
2015\\ipp\\include

set IPP\_LIB=C:\\Program Files (x86)\\Intel\\Composer XE
2015\\ipp\\lib\\intel64

set IPP\_ROOT=C:\\Program Files (x86)\\Intel\\Composer XE 2015\\ipp

Compiler options (REL\_C\_FLAGS is for release, DBG\_C\_FLAGS for debug)
------------------------------------------------------------------------

set DBG\_C\_FLAGS=/wd4996 /Zm120 /Zi
/D\_BIND\_TO\_CURRENT\_MFC\_VERSION=1
/D\_BIND\_TO\_CURRENT\_CRT\_VERSION=1
/D\_BIND\_TO\_CURRENT\_ATL\_VERSION=1 /D\_IPP\_NO\_DEFAULT\_LIB

set REL\_C\_FLAGS=/wd4996 /Zm120 /Zi
/D\_BIND\_TO\_CURRENT\_MFC\_VERSION=1
/D\_BIND\_TO\_CURRENT\_CRT\_VERSION=1
/D\_BIND\_TO\_CURRENT\_ATL\_VERSION=1 /D\_IPP\_NO\_DEFAULT\_LIB

set ADV\_LINK\_OPTS=/machine:AMD64 /LARGEADDRESSAWARE /SAFESEH:NO

Build order recommended:
------------------------

LMDB\\LMDB.vcxproj

GCFOS\_Client\\GCFOS\_Client.vcxproj

GCFOS\_Server\\GCFOS\_Server.vcxproj

GCFOS\_Server\\ConfigureDeduplicationServer\\ConfigureDeduplicationServer.csproj

GCFOS\_Server\\Installer\\DeduplicationServer\\DeduplicationServer.wixproj

Optional:
---------

GCFOS\_Client\_Managed\\GCFOS\_Client\_Managed.vcxproj

GENSHA1\\GENSHA1.vcxproj (Command line utility for testing client
operations, gives example client library usage)

GCFOS\_Tools\\GCFOS\_Tools.vcxproj (Command line utility for adding new
clients for global-mode)

### The GCFOS\_Server project has dependencies on the below assemblies.

&lt;Reference Include="AWSSDK.Core"&gt;

&lt;HintPath&gt;\$(DEV)\\Packages\\AWS\\v3\\Net45\\AWSSDK.Core.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="AWSSDK.S3"&gt;

&lt;HintPath&gt;\$(DEV)\\Packages\\AWS\\v3\\Net45\\AWSSDK.S3.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="Microsoft.WindowsAzure.Storage"&gt;

&lt;HintPath&gt;\$(DEV)\\packages\\Microsoft.WindowsAzure.Storage.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="Newtonsoft.Json"&gt;

&lt;HintPath&gt;\$(DEV)\\packages\\Newtonsoft.Json.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="openstacknet"&gt;

&lt;HintPath&gt;\$(DEV)\\packages\\openstacknet.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="SimpleRESTServices"&gt;

&lt;HintPath&gt;\$(DEV)\\packages\\SimpleRESTServices.dll&lt;/HintPath&gt;

&lt;/Reference&gt;

&lt;Reference Include="System" /&gt;

&lt;Reference Include="System.Configuration" /&gt;

The code was originally built with the following versions. Using newer
versions of the assemblies should be possible, but may necessitate minor
modifications to the source:

-   AWSSDK.Core 3.1.0.0 (Necessary for S3)

-   AWSSDK.S3 3.1.0.0

-   Micosoft.WindowsAzure.Storage 4.2.1.0

-   Newtonsoft.Json 4.5.0.0 (Necessary for OpenStack support)

-   openstacknet 1.3.0.0

-   SimpleRESTServices 1.3.0.0 (Necessary for OpenStack support)

As can be seen from the snippet of GCFOS\_Server.vcxproj above, all
packages are expected to be placed in the .\\Packages directory. The
easiest way to install packages for a project though is to use the NuGet
package manager console and execute the below commands (access console
via menu choice: Tools / NuGet Package Manager / Package Manager
Console):

> Install-Package AWSSDK.Core -Version 3.1.0
>
> Install-Package AWSSDK.S3 -Version 3.1.0
>
> Install-Package WindowsAzure.Storage -Version 4.2.1
>
> Install-Package Newtonsoft.Json -Version 4.5.1
>
> Install-Package SimpleRESTServices -Version 1.3.0
>
> Install-Package openstack.net -Version 1.3.5

Note that if you install these packages via the Package Manager Console,
you may need to edit the .vcxproj to delete the old references to ensure
that only the correct definition exists for each package.

When linking the GCFOS\_Server project, there are a few warnings caused
by linking with the LMDB package that can be ignored, e.g:

1&gt;Misc.obj : warning LNK4248: unresolved typeref token (01000024) for
'MDB\_txn'; image may not run

Installer
---------

You will not be able to build the installer
(./GCFOS\_Server/Installer/DeduplicationServer.wixproj) until you have
installed Wix, which can be downloaded from:

<http://wixtoolset.org/releases/>

Version 3.10.3.3007 was used during development.

You may need to edit the DeduplicationServer.wxs file so that it can
find the correct location for the Packages if they have been moved when
using the NuGet Package Manager.

Using GCFOS\_Server in “global mode”
====================================

You will need to compile the “UB\_Release” (Or “UB\_Debug”)
configuration and then use that binary created.
ConfigureDedupliationServer can be used as per normal to define where
the file store is to be located. **IMPORTANT:** You cannot currently
enable a block store in this mode.

The first time the GCFOS\_Server is ran, it will create a new credential
for client-1, the admin user. It will then store the secret key for this
user in the registry. This registry secret should be written down
somewhere safe because if it is lost, then it would not be possible to
access any administrative facilities of the server without significant
effort.

You may then use the GCFOS\_Tools.exe program to add/delete clients that
should be authorized to use the system. Of course, these simple client
functions (see source) can be inserted into any program to automate the
process for a typical deployment, but are included here to demonstrate
the use of the API. To add a new user for example, type at the command
line:

GCFOS\_Tools –a

It will respond back with something like the following:

Added client 2, key =
f2fdb538a5f42af21745042c8c37cb34abd5504b5c23eda6c8b4b52c353b4d6f

This information for the intended user should then be entered on all of
their client computers. For UltraBac, this would mean the following
entries would be created on each of the client computers.

HKLM\\SOFTWARE\\UltraBac Software\\GCFOS\\Client:

ClientID:REG\_SZ:1

SecretKey:REG\_SZ:
f2fdb538a5f42af21745042c8c37cb34abd5504b5c23eda6c8b4b52c353b4d6f

If it was desired to delete client 2, then use the following command:

GCFOS\_Tools -d 2

IMPORTANT: The GCFOS\_Tools program must be run with the credentials for
client ID 1 (the administrator user), therefore it is important NOT to
delete client 1 -- otherwise you will not be able to access the server
again.

Because it could be time consuming at client-2’s location to insert all
of the registry entries necessary for the client credentials when
connecting to the server, it is possible to have a local GCFOS\_Server
running at client 2’s location configured in “redirection mode”. Simply
install GCFOS\_Server on a computer in the network there (one would be
necessary for each subnet used), and run ConfigureDeduplicationServer
and click the “Configure Redirection Mode” button on the main screen. A
dialog is presented which states:

> Redirection mode enables this service to be used exclusively for
> auto-configuration of deduplication clients.
>
> To enable, provide the client-id/secret information provided to you by
> UltraBac.
>
> Select ‘Cancel’ if you want this server to provide deduplication
> services to clients directly.

The user then has the ability to enter the client ID and the
shared-secret (in hex) and a server to connect to.

After configuring a GCFOS server is redirection mode, whenever a GCFOS
client on the local subnet attempts to auto-configure, it will receive
the credentials from the server and make the registry entries necessary
automatically.

FAQ
===

**What if a client connects to multiple GCFOS servers?**

This should be avoided if local client caches are enabled because the
cache has to be invalidated. A client could learn/cache that one
hash/block is resident on the server and report that to the calling
application that it is resident, but if it were to connect to a
different server the hash may not actually be resident on that server.
In order to combat this situation, each server generates a unique
randomly generated server-validation value which is compared to the
client’s cached value. If they are different, then the client first
purges all of its cached data. This will result in slower operation for
that client for a while until its cache is rebuilt over time.

**What internet access is required for GCFOS to function?**

The GCFOS server listens on UltraBac’s IANA-assigned port 1910 to listen
for queries. The clients create ephemeral ports (at the discretion of
the sockets provider) in order to create connections to the GCFOS
server. From a firewall perspective, you must allow any port (or
ephemeral ports only) outbound to connect to port 1910. You must then
define an inbound rule from port 1910 back to either any port or the
ephemeral ports.

**What is the overhead to query GCFOS for files?**

The first backup of a path will involve the calculation for all hashes
for files encountered, as well as the query to the GCFOS server. The
results will be cached, and therefore subsequent backups of the same
path will be much faster. The overhead is very low, and any small
overhead is easily compensated by the time and storage saved by
eliminating thousands of common files in the backup.

**In the “global mode”, what prevents a malevolent actor from attempting
to download a file that does not belong to them if they know the hash?**

Let’s say that an authenticated user knows the hash of a certain mp3
file they wish to download but has never had access to, and makes an
attempt to retrieve it from the server. As part of the retrieval request
a 4-byte client-unique “validation key” is included. Although a
deterministic process is used to set/check the validation key, it
requires access to the first 1MB of file data. So, the actor would need
access to the first 1MB of file data in order to calculate the
validation key. If they had the file already in order to calculate this
key they wouldn’t need to retrieve it in the first place. Guessing the
validation key incorrectly results in the IP address being added to the
“banned” list, the session closed, and a wait period of 10 minutes or so
before being unbanned. A brute force attack would therefore require an
average of 147 million years.
