# Purezig

A freestanding & *fully*-static Zig binary that can call foreign functions via `dlopen`/`dlsym` without linking to libc.

## 1. How it works

I stole the idea from [this repo](https://github.com/Caesurus/foreign-dlopen) (which is written in C) and reimplemented it in Zig. The basic idea is:

1. Find a dynamic ELF binary on the system (e.g. `/bin/ls`, `/bin/sleep`, etc) that is linked against `libc.so`.
2. Load the ELF binary into memory manually (using `mmap` and reading the file).
3. Hijack the entry point of the ELF binary to jump back into our own code after the dynamic linker has initialized.
4. Make ld.so load it, which initializes the dynamic linker and loads `libc.so` into our process.
5. We get back control, locate the `dlopen` and `dlsym` symbols from `/proc/self/maps` by parsing libc's hash table.
6. Now we can call `dlopen`/`dlsym`!

Read [`src/simple_main.zig`](src/simple_main.zig) for the example code.

## 2. Limitations

- Linux x86_64 only (Possible to extend to other architectures, but not implemented yet)
- Requires a dynamic ELF binary on the system
- Dirty & hacky code

## 3. Run

```bash
$ zig build simple
[libc puts] hello via foreign dlopen
[libc printf] Number: 42, String: test
```

## Requirements

- Zig 0.15+
