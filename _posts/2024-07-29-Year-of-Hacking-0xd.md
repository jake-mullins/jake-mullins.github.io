---
layout: post
title: Week 13 - Time - BYUCTF 2024 C++ Reverse Engineering
tags: [year-of-hacking, reverse-engineering, ctf, c++]
---
This winter, I'll be taking [@legoclones](https://x.com/legoclones)/[Justin Applegate](https://www.linkedin.com/in/justin-applegate-b23676139/)'s Vulnerability Research and Reverse Engineering class for credit, and he gave me some challenges from BYUCTF 2024 to work through to keep my technical skills up to snuff. I breezed through this one, so the post is short this week. I'm getting into the habit of writing 500 words a day on different projects, so bigger and more impressive things are coming.

Thanks to Justin for helping me out, you are wicked smart and stunningly beautiful (please give me an A). Watch out for his DEFCON talk this August.

# Time
We get a simple 64-bit ELF binary that requires the existence of a file called `flag.txt`. After creating the file, it spits out this:
```shell
XOR Result:     205 155 252 133 189 74 225 200 162 239 73 188 62 238 128 224 100 170 226 91 241 175 32 164
```

However, trying it a few seconds later, it spits out a completely different answer.
```shell
XOR Result:     57 55 107 17 42 102 143 180 70 83 165 10 33 41 64 221 236 147 229 226 120 231 99 121
```

We can assume that this is some kind of representation of the `flag.txt` file. Running the binary multiple times in a second results in the same result, but only when within the same second. It looks like the output of the program is dependent on the system ztime.

Loading it up in Ghidra, we see that it was compiled in C++. I did a little bit of relabeling below.

```C++
undefined8 main(void)

{
  char file_is_open;
  bool is_end;
  int rand_int;
  time_t time;
  basic_ostream *xored_char;
  undefined8 uVar1;
  long in_FS_OFFSET;
  undefined8 begin_str;
  undefined8 end_str;
  basic_string *local_258;
  char *char_byte;
  basic_string file_content [32];
  basic_istream flag_file [520];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  std::basic_ifstream<>::basic_ifstream((char *)flag_file,0x102004);
                    /* try { // try from 001013d0 to 00101406 has its CatchHandler @ 001015b9 */
  file_is_open = std::basic_ifstream<>::is_open();
  if (file_is_open == 1) {
    std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 00101434 to 0010156a has its CatchHandler @ 001015a1 */
    std::getline<>(flag_file,file_content);
    std::basic_ifstream<>::close();
    time = ::time((time_t *)0x0);
    srand((uint)time);
    std::operator<<((basic_ostream *)std::cout,"XOR Result:     ");
    local_258 = file_content;
    begin_str = std::__cxx11::basic_string<>::begin();
    end_str = std::__cxx11::basic_string<>::end();
    while( true ) {
      is_end = __gnu_cxx::operator!=((__normal_iterator *)&begin_str,(__normal_iterator *)&end_str);
      if (!is_end) break;
      char_byte = (char *)__gnu_cxx::__normal_iterator<>::operator*
                                    ((__normal_iterator<> *)&begin_str);
      rand_int = rand();
      xored_char = (basic_ostream *)
                   std::basic_ostream<>::operator<<
                             ((basic_ostream<> *)std::cout,(int)*char_byte ^ rand_int % 0x100);
      std::operator<<(xored_char," ");
      __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&begin_str);
    }
    std::basic_ostream<>::operator<<((basic_ostream<> *)std::cout,std::endl<>);
    uVar1 = 0;
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)file_content);
  }
  else {
    xored_char = std::operator<<((basic_ostream *)std::cerr,"Error opening file \'flag.txt\'");
    std::basic_ostream<>::operator<<((basic_ostream<> *)xored_char,std::endl<>);
    uVar1 = 1;
  }
  std::basic_ifstream<>::~basic_ifstream((basic_ifstream<> *)flag_file);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}
```

This one is pretty straightforward. It takes the system time, which is represented as the number of seconds since January 1st, 1970. It then uses that as the seed for a random number generator. For every char, it uses this seeded random number generator to generate a new integer, take the least significant byte of that new integer, and XOR it with the char. It will then print it out as an unsigned integer.

We can cook up a simple C++ program to take the output of the `time` program and use the current system time to replicate the process:

```C++
#include <ctime>  
#include <iostream>  
  
// Usage:  
// ./solve $(./time) or $(nc <host> <target>)  
int main(int argc, char** argv) {  
   int time = std::time((time_t *) 0x0);  
   std::srand(time);  
  
   for (uint i = 3; i < argc; ++i) {  
       std::cout << static_cast<char>(std::stoi(argv[i]) ^ rand() % 0x100); 
   }  
   std::cout << std::endl;  
}
```

Because this is after the CTF is over, the netcat port that is affiliated with this challenge is down. I'll have to bother the guy who runs it (who TA'd for me about 3 separate times) to see if we can't turn it back on for practice. We'll just have to settle for running the `time` binary locally like this:
```shell
> ./solve $(./time)  
byuctf{fake_flag_bozo_get_good}
```

C++ reverse engineering has always been a little intimidating because of the more difficult syntax, but this has been a nice way to get my feet wet.

Thanks to Justin for helping me out, may your brain be ever [unrotted](https://x.com/jakemullins0_t/status/1789792652977914056).

## Music from this week
[Movin' Down the Line](https://open.spotify.com/track/3d1NQh0KOhJqo0Qr4w827X?si=7a4a973a8f934f5c) - Hoyt Axton
[Saddle Tramp](https://open.spotify.com/track/68FTJoO8edSpzuYb6lGW6P?si=93d6dd3fb7f24236) - Marty Robbins
