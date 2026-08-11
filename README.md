# Emulate-Hyperion

This guide took me a lot of time to write.

If you have any questions just join my discord and ping me : https://discord.gg/CgFPbvSaU



>This guide is a complete walkthrough of a Roblox Hyperion emulator, reverse engineered from `Cosmic Emulator (wich appears to be Volt emulator)`.

>Author : Krypt
>Join my discord for any questions : https://discord.gg/CgFPbvSaU


---


## TL;DR

Initialy i thought the emulator was a bytecode VM. But it appears to be a fault driven on demand page decryptor that runs Hyperion's own native code.

1. Hyperion's application code (the `.boot` section, 6 MB) is native code, but its encrypted in memory (ChaCha20) and its pages are non-executable.

2. When the CPU tries to execute an encrypted page the error -> **`STATUS_ACCESS_VIOLATION`**

3. A VEH catches the fault, identifies the faulting page, calls an translator that decrypts the page on demand, rebases its internal pointers, and patches `Rip` to the now clear code.

4. Execution resumes (`EXCEPTION_CONTINUE_EXECUTION`) -> native Hyperion code runs clearly.

5. Every new page repeats this cycle. Hyperion calls its own approximate 3700 functions, herlper routines kept in clear in `.themida`, and windows APIs - wich it calls not by name but through a table of pointers it builds directly, looking up each Windows function by a fingerprint instead of its name.


I figured out the "emulated" code is Hyperion's own code, executed after page by  page decryption. The "VM" is the VEH + translator + crypto machinery that decrypts and presents pages on demand.

And for the "Emulation" (if we can call it that way) the protector does not blind Hyperion (no patching / filtering / faking its checks). It runs authentic Hyperion, apart from the cheating client : an isolation runtime + a clean host (checks pass = ud) + unfiltered real APIs (the full winsock stack is exposed to `.boot`) -> Hyperion sends and authentic "clean" heartbeat to Roblox servers and answers "ok" to the game client over a local IPC channel, while the real game process separated isn't being scanned.


---


## Step 0 - IDK Just a clarification

A Hyperion emulator is 2 things joined together : 

1. A program that hosts Hyperion's code : decrypts pages on demand, resolves Windows APIs by hash, hides itself, and runs on a clean host.

2. The real Hyperion payload, encrypted, running normally inside that runtime but apart from the game client whre yall are cheating

The whole point : **YOU NEVER MODIFY HYPERION'S BEHAVIOUR**


---


## Step 1 - Binary layout



Layout of the emulator : 

| Section    | State       | What it is                                                            |
| ---------- | ----------- | --------------------------------------------------------------------- |
| `.text`    | *cleartext* | The runtime : VEH, translator, APi resolver, trampoline, crypto setup |
| `.rdata`   | *cleartext* | Cosntants, ChaCha20                                                   |
| `.boot`    | *encrypted* | The payload -> Hyperion's 6 mb of code                                |
| `.data`    | *encrypted* | payload data                                                          |


---


## Step 2 - Jump into the encrypted code on  purpose to trigger a fault

`DllMain` spawns a thread that loads the payload entry point into `rax` and does a `jmp rax` into the encrypted / non executable page. That jump raises an `ACCESS_VIOLATION` wich is exactly what is searched, the VEH waits for this fault to be done.


```asm
push rbp/r15/r14/r13/r12/rsi/rdi/rbx
sub rsp, 0x338
mov rax, [rip+0x150d62]

mov dword [rsp+0xdc], 0x66dd4c96
movabs rax, 0xe601b1bf38925eaf
movabs rax, 0x23658a2d8887ad37

...(a lot of 64bits immediates)
call sub_7FFAB6432160
call sub_7FFAB647E250
```


`sub_7FFAB647E250` calls the **trampoline** `sub_7FFAB648FBB0`, which is a one-instruction `jmp rax`:


```c

sub_7FFAB648FBB0() { return (*rax)(); }   // jmp rax

```


`rax` was loaded with the payload entry point ( RVA `0xC50000`). The jump lands on and encrypted / non executable page -> **`STATUS_ACCESS_VIOLATION` (0xC0000005)** with 
`ExceptionInformation[0] == 8` (an execute fault - what we are searching to make here).



---



## Step 3 - VEH : catch execute faults on encrypted pages


The role of this Step is to install one vectored exception handler that filters only execute faults which address is inside the payload, it then calls the translator to decrypt that page, and patches  `Rip` to the cleartext. Everything is untouched.



```c

__int64 register_veh(__int64 a1) {    // a1 = emulator module base

    memset(&managed_pages, 0, sizeof(managed_pages));

    page_count = 0;

  

    parse_pe(pe_ctx, a1);       // validate MZ/PE/AMD64/PE32+

    if (pe_ctx.valid) {

        for (int i = 0; i < pe_ctx.section_count && page_count < 32; i++) {

            get_section(pe_ctx, sec, i);

            if (sec.is_code && (sec.flags & 0x20)) { // IMAGE_SCN_CNT_CODE

                managed_pages[page_count].lo = sec.va;

                managed_pages[page_count].hi = sec.va + sec.size;

                page_count++;

            }

        }

        veh_handle = AddVectoredExceptionHandler(1, veh_wrapper); // FirstHandler=1

    }

    return veh_handle != 0;

}

```




The PE parser validates the image is a 64 bit PE32+ (`"MZ"` 0x5A4D, `"PE"` 0x4550, machine `0x8664` AMD64, magic `0x20B` PE32+) and walks the section table (`e_lfanew + SizeOfOptionalHeader + 24`). Only `IMAGE_SCN_CNT_CODE` sections become "managed" pages, that is how `.data` is exlcuded ans it stays encrypted.




```c

//   handled → 0xFFFFFFFF = EXCEPTION_CONTINUE_EXECUTION

//   pass    → 0x00000000 = EXCEPTION_CONTINUE_SEARCH

__int64 veh_wrapper() { return -(unsigned __int8)veh_handler(); }

  

char veh_handler(EXCEPTION_POINTERS *a1) {

    EXCEPTION_RECORD *er = a1->ExceptionRecord;

    CONTEXT *ctx = a1->ContextRecord;

    if (!er || !ctx) return 0;

  

    if (er->ExceptionCode != 0xC0000005)        return 0;  // only ACCESS_VIOLATION

    uint64_t fault_addr = er->ExceptionAddress;

    if (ctx->Rip != fault_addr)                  return 0; // fault at current instruction

    if (er->NumberParameters < 2)                return 0;

    if (er->ExceptionInformation[0] != 8)        return 0; // only EXECUTE fault

    if (er->ExceptionInformation[1] != fault_addr) return 0;


    if (!in_managed_table(fault_addr))           return 0;

  

    uint64_t clear = translator(fault_addr);   // decrypt + rebase

    if (clear) {

        ctx->Rip = clear;     // PATCH RIP -> cleartext

        return 1;            // EXCEPTION_CONTINUE_EXECUTION

    }

    return 0;  // couldn't handle -> pass

}
```




In short, this VEH is for page decryption, not anti debugging (putting this here cuz i initially thought it was).

It decrypts code on demand, it only catches `0xC0000005` execution faults on protected memory pages to decrypt them.
It ignore debuggers, you shouldn't bloat this with anti debug logic, keep it straight forward to a memory decryption.


---



## Step 4 - Translator : decrypt the page, rebase pointers, resume



A. On the execute fault, the translator takes a spinlock so concurrent fault thread don't race.
B. Decrypts the faulting page with ChaCha20.
C. Rebases every pointer in the page by adding the module base.
D. Jumps to the cleartext code.

There is never any inspection or patches into Hyperion.

**Spinlock + TEB**

```c

while (1) {

    if (_InterlockedCompareExchange(lock, 1, 0) == 0)  // CAS(lock, 1, 0)

        break;  // acquired

    _mm_pause();

}

// record which thread decrypted this page (for re encryption / anti-dump)

ownership = (uint32_t)page_id | (NtCurrentTeb() << 32);

*page_owner_slot = ownership;

```


**Uniform Rebase loop**

```c

v23 = pointer_table;
v24 = 1126;

while (v24) {

    *v23 += 2129516248LL;  // += K 

    *v23 += base;  // += module base  <- THE REAL REBASE

    *v23++ -= 2129516248LL;     // -= K   (cancels the += K)

    v24--;

}

__asm { jmp qword ptr [rax] }   // resume on the cleartext, rebased page

```


The `+= K` / `-= K` is junk to hide the real operation from static analysis, the net effect is `*ptr += base` for all 1126 pointers. This is what PE loader does applying `IMAGE_REL_BASED_DIR64` relocation.
Then `jmp [rax]` resumes execution.

**The translator does decryption + uniform rebase + jmp, it does not NOP, redirect or patch any Hyperion check.**



---


# Step 5 - Encryption of the paylod, decrypt one page at a time.


The role is to encrypt the payload (ChaCha20, sigma `expand 32-byte k`). At runtime, decrypt only the page that just faulted, not the whole payload. Keep the key temporary on the stack so it can't be scraped from a heap dump.


**The crypto chain**

```
setup(ctx)        builds the ChaCha20 context on the stakc

wrapper(ctx)      rcx = [rbx+0x1D8] = key context

orchestrator(ctx) dispatches to 3 SIMD primitives
```


**Key is stack local and temporary**


```asm

; just to be clear, the key context is a stack frame not a global

sub  rsp, 0x478           ; 1144 byte frame

mov  rbx, rsp             ; rbx = stack

; the 6 key are written to the stack, exist for ~1 ms, then gone

movabs rax, <key_imm0> ; mov [rbx+0x228], rax

movabs rax, <key_imm1> ; mov [rbx+0x230], rax

```


There is **no `lea rbx,[rip+...]`**, the key never lives at a fixed address.

**Why per page decryption matters :** the decrypt call is reached bia a data dispatch table (a pointer table), so only pages that actually execute get decrypted ( like i said so many time). Combined with re encryption pages after (Step 4), this is the anti dump method.



**How to get cleartext without the key :** the emulator decrypts pages in place at `module_base + RVA`, and the ceartext persists in memory untiil the protector tears down.
A dumper (`OpenProcess` + `VM_READ`, no debug port so the anti debug never triggers) reads the cleartext straight out of the live process.



---



## Step 6 - Resolve Windows API by hash


A normal dll lists its imports by name in the IAT. the emulator instead has one PE import 
(`GetModuleHandleA`) and resolves everything else by hash when it runs, wlaking the PEB to find real exports.
**There are 2 hash systems :** One for the payload's imports, and on for the runtime own API.


**Payload imports - FNV-1a-64**


```python
FNV_OFFSET = 0xCBF29CE484222325

FNV_PRIME  = 0x100000001B3

def fnv1a64(name: bytes) -> int:

    h = FNV_OFFSET

    for b in name:

        h ^= b

        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF

    return h

# item.flag == 0 -> resolve by name

# item.flag != 0 -> resolve by ordinal
```


Each item in the import table is `[iat_ptr][hash_export][ordinal][flag]`. The loader walks each loaded DLLs exports, hashes each export name and fills the runtime IAT slot when the hash matches.



**Runtime APIs**


```c
// m = 0xC6A4A7935BD1E995, gamma = 0x94D049BB133111EB (always)

// THE SEED IS PER RESOLVER (not a fixed seed)

uint64_t murmur_custom(const char *name, uint64_t seed) {

    uint64_t h = seed;

    for (unsigned char b; (b = *name++); ) {

        if (b >= 'A' && b <= 'Z') b += 32;

        uint64_t t = b ^ ROL64(h, 13);

        t *= M;  t ^= t >> 27;

        h  = GAMMA * t;  h ^= h >> 31;

    }

    return h;

}
```


Each resolver walks the PEB `InLoadOrderModuleList`, hashes each module's `BaseDllName` and each export, and it returns the real export pointer when the hash matches its store target. The per resolver means that even if you break the algorithm you won't be able to build one hash table, each API needs its own seed.



**Direct Getters / Direct Thunks**

The resolved pointer is stored in a **XOR obfuscated dispatch table** (`ptr_resolver XOR 0x087FDF1F9A2C609D`), and wrappers are `jmp rax` thunks :

```c

wrapper() { trampoline(); return trampoline(); }   // trampoline = jmp rax

// deobfuscate pointers -> resolver -> real API ptr -> jmp rax

```


Resolvers are pure getters, PEB walk -> real export, no filtering of the return value. Anti VM APIs like `GetSystemFirmwareTable` reach the payload unfiltered, so Hyperion reads the real SMBIOS.
Do not modify / wrap the API results it would be detected.



---



## Step 7 - Module Stomping


If you dont know about module stomping i guess just skid my injector : [Demos427/Module-Stomping-Injector](https://github.com/Demos427/Module-Stomping-Injector)

You need to change things, it injects into roblox so that is not what we want here.



# Architectural Summary

The system does not emulate the internal logic of the anti-cheat, but it changes its **native execution environment**. By separating Hyperion into a clean, isolated process and relaying its authentic network and local IPC responses back to the server and client.
This "emulator" does not patch anything.

<img width="975" height="657" alt="image" src="https://github.com/user-attachments/assets/44441323-e7a7-4ff1-9a8f-55b5cd7237f4" />




