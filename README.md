# NVMeDirect

NVMeDirect is a user-space I/O framework for NVMe SSDs, which allows user
applications to access the storage device directly. This will enable various
application-specific optimizations on NVMe SSDs.
For further details on the design and implementation of NVMeDirect, please
refer to the following [paper](https://www.usenix.org/conference/hotstorage16/workshop-program/presentation/kim).

- Hyeong-Jun Kim, Young-Sik Lee, and Jin-Soo Kim, "NVMeDirect: A user-space I/O Framework for Application-specific Optimization on NVMe SSDs,"
Proceedings of the 8th USENIX Workshop on Hot Topics in Storage and File
Systems (HotStorage), Denver, Colorado, USA, June 2016.


## How to build and run

To build the kernel module and shared library,

    $ make

To install the kernel module, shared library, and header file,

    $ sudo make install

This will install the following files:

- nvmed.ko in /lib/modules/$(shell uname -r)/extra

- lib_nvmed.h in /usr/local/include

- libnvmed.so in /usr/local/lib

- nvmed_admin in /usr/local/bin

To load the NVMeDirect module into the kernel,

    $ sudo modprobe nvmed

The root can restrict the users of the NVMeDirect framework and the number of
I/O queues per user using the user-space tool, nvmed_admin.

    $ sudo nvmed_admin /dev/nvme[device id]n[namespace id] set [user name] [queue count]

Finally, link your program with the NVMeDirect library and run!


## How to use NVMeDirect APIs

Please refer to the [NVMeDirect-APIs.md](https://github.com/nvmedirect/nvmedirect/blob/master/NVMeDirect-APIs.md) file.


## Contacts

The NVMeDirect framework is being currently maintained by [Computer Systems 
Laboratory](http://csl.skku.edu) in Sungkyunkwan University, South Korea. 
NVMeDirect is an on-going work and we welcome your contribution and feedback. 
If you have any questions or suggestions, please contact the following people.

- Hyeong-Jun Kim (hjkim@csl.skku.edu)

- Jin-Soo Kim (jinsookim@skku.edu)
