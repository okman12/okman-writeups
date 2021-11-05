# AngstromCTF - Califrobnication

> It's the edge of the world and all of western civilization.
>
> The sun may rise in the East at least it's settled in a final location. It's understood that Hollywood sells Califrobnication.
>
> You get source for this one. Find the flag at /problems/2020/califrobnication on the shell server.
>
> Author: kmh11

This is the file we're provided - califrobnication.c

```c
#include <stdio.h>
#include <string.h>

int main() {
	FILE *f;
	char flag[50];
	f = fopen("flag.txt", "r");
	fread(flag, 50, 1, f);
	strtok(flag, "\n");
	memfrob(&flag, strlen(flag));
	strfry(&flag);
	printf("Here's your encrypted flag: %s\n", &flag);
}
```

We're also provided an output of the program, in flag.txt`Here's your encrypted flag: u\x18KKKuI^WK\x1eOLK\x1b\x1fHNu^\x12C\x1cXLE\x1aDCFC\x1eEGINQX\x1bI\x1fILL\x13DNE`

The first part is simple - according to the man page for memfrob,

```
   The  memfrob() function encrypts the first n bytes of the memory area s
   by exclusive-ORing each character with the number 42.  The  effect  can
   be reversed by using memfrob() on the encrypted memory area.
```

So first xoring the output by 42, we obtain this - `_2aaa_ct}a4efa15bd_t8i6rfo0nili4omcd{r1c5cff9ndo`, but now we have a problem - according to the manpage for strfry,

```
   The  strfry()  function  randomizes  the  contents  of  string by using
   rand(3) to randomly swap characters in the string.  The  result  is  an
   anagram of string.
```

At first, it seems like we have no choice but to randomly permute the string until we get the solution - and we can make some educated guesses about the format, it's surrounded by actf{} and probably contains the word "california" or "califrobnication", but previous flags have had an apparently random hexadecimal component at the end, past the legible flag part, to prevent you just guessing them - this makes simply brute forcing it unfeasible.

So, what do you do? Our only hope will be if the man page is wrong and/or deceptive - while it says "random" it doesn't specify how this randomness is generated. If it's from a truly random source, i.e. /dev/urandom, /dev/random, getrandom(), etc, then we'll be out of luck...

But, miraculously, I found my way to this link - [https://code.woboq.org/userspace/glibc/string/strfry.c.html](https://code.woboq.org/userspace/glibc/string/strfry.c.html) - containing the source code for the strfry function,

```c
char *strfry (char *string)
{
  static int init;
  static struct random_data rdata;

  if (!init)
    {
      static char state[32];
      rdata.state = NULL;
      __initstate_r (time ((time_t *) NULL) ^ getpid (),
		     state, sizeof (state), &rdata);
      init = 1;
    }

  size_t len = strlen (string);
  if (len > 0)
    for (size_t i = 0; i < len - 1; ++i)
      {
	int32_t j;
	__random_r (&rdata, &j);
	j = j % (len - i) + i;

	char c = string[i];
	string[i] = string[j];
	string[j] = c;
      }

  return string;
}
```

lo and behold, if we look at how the random number generator is seeded here, with the line `__initstate_r (time ((time_t *) NULL) ^ getpid (), state, sizeof (state), &rdata)` - this seeds it with completely predictable data! `time(NULL)` returns the current UNIX time (seconds since epoch) and `getpid()`, predictably, returns the PID of the process this is running in - the state is simply these two integers combined via XOR.

So, all we need to recreate the random state is the time the program was run, and the PID of the process it ran in - then we can simply run through the same steps as the program to find out which letters were swapped, and de-fry our flag!

After some fiddling around, I came up with a bash one liner that executes the program, tells me the PID of the process that just ran, and gives me the current UNIX time in seconds -

```bash
sh -c 'echo $$; exec ./califrobnication | xxd -p > ~/out'; date "+%s"
```

From this, I got a PID (13526) and a time (1584294985). As it turns out, this time was slightly off - but we'll get to that. From here, looking at the part of strfry that actually handles the shuffling,

```c
    for (size_t i = 0; i < len - 1; ++i)
      {
	int32_t j;
	__random_r (&rdata, &j);
	j = j % (len - i) + i;

	char c = string[i];
	string[i] = string[j];
	string[j] = c;
      }
```

We can see that it shuffles each character once, iterating over the given string. For each character, it chooses a random number (j), then performs a modulus with the length of the string, adding the current index to the result - this chooses a new position in the string between the chosen character and the end of the string. Finally, the character at the new position and the character at the current position are swapped - and note that this is in-place, so the string being iterated over is being modified each time.

To reverse this, we need to quite literally reverse this - we select the same j values that the program selected, but apply the swaps in reverse, starting our iteration from the end of the string rather than the start and using the last generated j value first.

As I mentioned above, my time was slightly off - but knowing the flag format starts actf{ and ends } meant with some rudimentary brute forcing, I could calculate the correct seed easily - a completed C program to solve this is as follows

```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include <stdbool.h>


void main() {

	//int pid=13526;
	//int time = 1584294985;
	// one of these was slightly off
	// 1584289992 is the seed
	char output[] = "rnci5lmdi_14of8a9{a_5bod}ifaed6canf4cf20orc_tt1a";
	size_t len = strlen(output);
        int32_t j_vals[len];
        int32_t curr_j;
        struct random_data rdata;
        char c;
        static char state[32];
        
        // initialise random number generator
        rdata.state = NULL;
        //__initstate_r (time ^ pid, state, sizeof (state), &rdata);
        initstate_r(1584289992, state, sizeof (state), &rdata);
        // the way it works is
        // it iterates over each item in the list, choosing a random j value
        // it then mods the j value to get a value within the length of the list
        // and swaps the char at i with the char at j
        // so to undo this, we have to generate all of the j values, then go in reverse

        for (int i = 0; i < len - 1; ++i) {
	    //__random_r(&rdata, &j_vals[i]);
	    random_r(&rdata, &j_vals[i]);
	}
	// now we have all the j vals, go in reverse
	for (int i = len - 1; i >= 0; --i) {
	    curr_j = j_vals[i] % (len - i) + i;
            printf("%i|%i\n",j_vals[i],curr_j);
	    c = output[i];
	    output[i] = output[curr_j];
	    output[curr_j] = c;
        }
        
        puts(output);
}
```

Compiling and running this gives us the flag - `actf{dream_of_califrobnication_1f6d458091cad254}`!

I really enjoyed this challenge, showing off a peculiarity with a little-known C standard library function and encouraging me to find a weakness in somewhere you normally never look!
