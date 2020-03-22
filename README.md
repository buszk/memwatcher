# MemWacher for C/C++
MemWatcher is a dynamic library for C/C++ that add hooks to memory access at requested memory area. It achieve so by Linux mprotect syscall under the hook. The watch hook is long lived until removed through our API. Currently, the project only support Linux x86_64, but the idea could be easily ported to other linux architectures.

## Design
When a region is under watch, we first set the pages as `PROT_NONE`. Access to these page will trigger sigsegv which is dispatched to our segment fault handler.

The handler founds that the cause of segfault is our watched page. It allocates a payload page to execute the faulted instruction. It also set the page as `PROT_READ|PROT_WRITE` to temporarily enable access.

The handler returns to payload page execute the faulted instruction. The second instruction cause another segfault.

The handler founds that the cause of segfault is our payload page. It triggers callback and memory is tracked. Lastly, it reset page permission to `PROT_NONE`, and returns to the next instruction. The execution carries on from here.

## Compile
At first, you will need to install dependencies [Zydis](https://github.com/zyantific/zydis).
```
git clone --recursive https://github.com/zyantific/zydis
cd zydis
mkdir build && cd build
cmake ..
make
sudo make install
```
Then you can build MemWatcher by following the commands below.
```
git clone https://github.com/buszk/memwatcher.git
make
make test
```

## API
Add a region to our watch list
```
void _watch_address(void *addr, size_t size, int prot);
```
Remove a region from our watch list
```
void _unwatch_address(void *addr, int prot);
```
For real examples, check our test cases `test_*.c`.

## Debugging
Debugging your program may become hard after using a custom segfault handler. Try `handle SIGSEGV nostop noprint pass`  in gdb. If debugging a segfault, try `break _real_segfault`. For example run 
```
gdb -ex "handle SIGSEGV nostop noprint pass" -ex "break _real_segfault" -ex "r" ./test_segfault
```

```
$ bt
#0  _sigsegv_protector (s=<optimized out>, sig_info=0x7fffffffd8b0, vcontext=0x7fffffffd780) at memwatcher.c:365
#1  <signal handler called>
#2  main () at test_segfault.c:3
#3  0x00007ffff77e6b97 in __libc_start_main (main=0x5555555562f0 <main>, argc=0x1, argv=0x7fffffffdf18, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdf08) at ../csu/libc-start.c:310
#4  0x00005555555563ca in _start ()
```

## Limitations
Multithreading access is not garanteed to be tracked under the project design. The best usecase is that tracked region/page should only be accessed by the same thread. If you want to debug multithreading access to the same memory, this tool is not the best for you. For more information, reading the design section. 