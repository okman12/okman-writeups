# ALLES!CTF - Jumpy

This was a novel pwn challenge from ALLES!CTF, involving using misalignment and hiding instructions within to escape a miniature assembler.

We're given this code, jumpy.c -

```c
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>

void ignore_me_init_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

typedef struct instruction_t
{
    char *mnemonic;
    uint8_t opcode;
} instruction_t;

const uint8_t OP_RET = 0xc3;
const uint8_t OP_SHORT_JMP = 0xeb;
const uint8_t OP_MOV_EAX_IMM32 = 0xb8;

const instruction_t INSNS[3] = {
    {"ret", OP_RET},
    {"jmp", OP_SHORT_JMP},
    {"moveax", OP_MOV_EAX_IMM32},
};

uint8_t *cursor;
uint8_t *mem;

void emit_opcode(uint8_t opcode)
{
    *cursor++ = opcode;
}
void emit_imm32()
{
    scanf("%d", (uint32_t *)cursor);
    cursor += sizeof(uint32_t);
}

int8_t emit_imm8()
{
    scanf("%hhd", (int8_t *)cursor++);
    return *(int8_t *)(cursor - 1);
}

const instruction_t *isns_by_mnemonic(char *mnemonic)
{
    for (int i = 0; i < sizeof(INSNS) / sizeof(INSNS[0]); i++)
        if (!strcmp(mnemonic, INSNS[i].mnemonic))
            return &INSNS[i];
    return NULL;
}

bool is_supported_op(uint8_t op)
{
    for (int i = 0; i < sizeof(INSNS) / sizeof(INSNS[0]); i++)
        if (op == INSNS[i].opcode)
            return true;
    return false;
}

int main(void)
{
    ignore_me_init_buffering();
    printf("this could have been a V8 patch...\n");
    printf("... but V8 is quite the chungus ...\n");
    printf("... so here's a small and useless assembler instead\n\n");

    mem = mmap((void*)0x1337000000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(mem, 0xc3, 0x1000);
    cursor = mem;

    printf("supported insns:\n");
    printf("- moveax $imm32\n");
    printf("- jmp $imm8\n");
    printf("- ret\n");
    printf("- (EOF)\n");
    printf("\n");

    uint8_t **jump_targets = NULL;
    size_t jump_target_cnt = 0;

    {
        while (1)
        {
            printf("> ");
            char opcode[10] = {0};
            scanf("%9s", opcode);
            const instruction_t *insn = isns_by_mnemonic(opcode);
            if (!insn)
                break;

            emit_opcode(insn->opcode);
            switch (insn->opcode)
            {
            case OP_MOV_EAX_IMM32:
                emit_imm32();
                break;
            case OP_SHORT_JMP:
                jump_targets = reallocarray(jump_targets, ++jump_target_cnt, sizeof(jump_targets[0]));
                int8_t imm = emit_imm8();
                uint8_t *target = cursor + imm;
                jump_targets[jump_target_cnt - 1] = target;
                break;
            case OP_RET:
                break;
            }
        }
    }

    for (int i = 0; i < jump_target_cnt; i++)
    {
        if (!is_supported_op(*jump_targets[i]))
        {
            printf("invalid jump target!\n");
            printf("%02x [%02x] %02x\n", *(jump_targets[i] - 1), *(jump_targets[i] + 0), *(jump_targets[i] + 1));
            exit(1);
        }
    }

    uint64_t (*code)() = (void *)mem;
    mprotect(code, 0x1000, PROT_READ | PROT_EXEC);
    printf("\nrunning your code...\n");
    alarm(5);
    printf("result: 0x%lx\n", code());
}
```

This is quite hefty, so we'll break down what it does in chunks -&#x20;

```c
    printf("this could have been a V8 patch...\n");
    printf("... but V8 is quite the chungus ...\n");
    printf("... so here's a small and useless assembler instead\n\n");

    mem = mmap((void*)0x1337000000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(mem, 0xc3, 0x1000);
    cursor = mem;
    
    printf("supported insns:\n");
    printf("- moveax $imm32\n");
    printf("- jmp $imm8\n");
    printf("- ret\n");
    printf("- (EOF)\n");
    printf("\n");

    uint8_t **jump_targets = NULL;
    size_t jump_target_cnt = 0;
```

main first informs us that this could have been a v8 patch, but it isn't (thank god - look at my Kit Engine and Download Horsepower writeups if you want to see the horror of v8 exploitation). Next, it maps 0x1000 bytes of memory at a very elite address (0x1337000000), marking the memory region as RW - no execute permissions. Lastly, it sets the every byte in the region to be 0xc3 - this is a clue for what this section is going to be used for later, because this is an encoding for the `ret` instruction - [https://www.felixcloutier.com/x86/ret](https://www.felixcloutier.com/x86/ret) - and it informs us that the "supported instructions" are moveax with a 32 bit immediate, jmp with an 8 bit immediate and ret.

```c
    {
        while (1)
        {
            printf("> ");
            char opcode[10] = {0};
            scanf("%9s", opcode);
            const instruction_t *insn = isns_by_mnemonic(opcode);
            if (!insn)
                break;

            emit_opcode(insn->opcode);
            switch (insn->opcode)
            {
            case OP_MOV_EAX_IMM32:
                emit_imm32();
                break;
            case OP_SHORT_JMP:
                jump_targets = reallocarray(jump_targets, ++jump_target_cnt, sizeof(jump_targets[0]));
                int8_t imm = emit_imm8();
                uint8_t *target = cursor + imm;
                jump_targets[jump_target_cnt - 1] = target;
                break;
            case OP_RET:
                break;
            }
        }
    }
```

&#x20;Now we enter the while loop which takes our input - as you could have guessed from what it printed previously, this is a miniature assembler - and it only allows three instructions, the three we were shown before - these are translated as

```c
const uint8_t OP_RET = 0xc3;
const uint8_t OP_SHORT_JMP = 0xeb;
const uint8_t OP_MOV_EAX_IMM32 = 0xb8;

const instruction_t INSNS[3] = {
    {"ret", OP_RET},
    {"jmp", OP_SHORT_JMP},
    {"moveax", OP_MOV_EAX_IMM32},
};
```

The ret we've seen before, filling the memory page - we also have the first byte of a short jump instruction ([https://www.felixcloutier.com/x86/jmp](https://www.felixcloutier.com/x86/jmp)) and the first byte of a `mov eax, 32_bit_immediate` instruction ([https://www.felixcloutier.com/x86/mov](https://www.felixcloutier.com/x86/mov)). The loop itself is very simple - it reads up to 9 characters of an opcode (stopping at whitespace) into opcode, and verifies the opcode is valid. If it is, it uses an additional emit\_x function to emit the right sized immediate for the function - i.e. a 32 bit integer for the moveax function, taken in via %d. We can send as many instructions as we want, stopping at an EOF or an invalid opcode - although if we exceed more than 0x1000 bytes of output we'll run off the end of the mapped page and crash when writing the next opcode. The most interesting of the 3 instructions by far is jmp - the writer has levied an additional restriction on the jmp instruction,

```c
            case OP_SHORT_JMP:
                jump_targets = reallocarray(jump_targets, ++jump_target_cnt, sizeof(jump_targets[0]));
                int8_t imm = emit_imm8();
                uint8_t *target = cursor + imm;
                jump_targets[jump_target_cnt - 1] = target;
                break;

...
    for (int i = 0; i < jump_target_cnt; i++)
    {
        if (!is_supported_op(*jump_targets[i]))
        {
            printf("invalid jump target!\n");
            printf("%02x [%02x] %02x\n", *(jump_targets[i] - 1), *(jump_targets[i] + 0), *(jump_targets[i] + 1));
            exit(1);
        }
    }
```

It stores an array of all the addresses which our jump instructions target, and once we've finished providing our input it checks each of the target addresses - verifying that the opcode targeted is one of the 3 provided by the assembler.

```c
    uint64_t (*code)() = (void *)mem;
    mprotect(code, 0x1000, PROT_READ | PROT_EXEC);
    printf("\nrunning your code...\n");
    alarm(5);
    printf("result: 0x%lx\n", code());
```

Finally, C is convinced that the pointer to the start of the page where we wrote our input is actually a function that returns a 64 bit integer. It then changes the protections of the page from RW to RX, preventing self modifying code (which would require RWX), sets a 5 second timer, runs our code and tells us the result.

So, how do we exploit it? The ret and moveax are useless on their own - the ret will just transfer back to the main function, and overwriting the value in eax does not help us - the only instruction we can possibly use to break out is the jmp. The key is in the extra check added to the jmp - why check if the target is a valid opcode if you can only emit those opcodes? The check is to prevent this scenario -&#x20;

```
jmp 1; mov eax 0x90909090;

in bytes, this is

eb01b890909090
   |  ^
   ----
```

The arrow shows the path of the jump - because it jumps into the immediate part of the instruction, rather than hitting the first byte of the mov, it begins executing at the 0x90 - this is a nop. In this way, we could store four-byte instructions inside moveax's, and run them via a jmp, chaining them together in the order mov, jmp, mov, jmp, etc. However, they have specifically prevented this with the extra check on the jmp - luckily, they don't check to an arbitrary depth - only the instructions which were originally jmps! This means that if we hide a short jump inside a moveax, and then jump to that, we can bypass the check - because it will detect the target of the second jump to be a valid opcode, another short jump, as shown in this example -

```
jmp 1; mov eax 0x909003eb; mov eax 0x90909090;

in bytes, this is

eb01b8eb039090b890909090
   |  ^  |      ^
   ----  --------

```

By chaining these together, we can execute a maximum of one 4 byte instruction per 12 bytes, more than enough to give myself a shell! For a challenge, it's also possible to solve this by chaining together 2 byte instructions (before the short jump) every 5 bytes for slightly better efficiency, but getting a shell with only 2 byte instructions requires considerably more instructions (although it is definitely possible, as I have done it for a previous challenge - lots of implicit imuls!). All that's left for us to do now is to write a 64 bit assembly stub to give us a shell (being careful to use no more than 4 bytes per instruction) and transform it into a chain of jmps and moveax's for the program.

My code to do this is below - I didn't have to store /bin/sh somewhere and point to it because my last input is stored on the stack - since the program stops receiving input and runs my code upon receiving EOF or an invalid instruction, I can send my payload, followed by /bin/sh\x00, to store that string on the stack ready for me to use it in my execve() call.

TODO: include code
