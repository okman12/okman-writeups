# AngstromCTF - LIBrary in C

> After making that trainwreck of a criminal database site, clam decided to move on and make [a library book manager](https://files.actf.co/e30d6d3dd83faaeb47dbe49642386c8c5fa2d39f3a948889ff7a2d8cdc39a365/library_in_c) ... but written in C ... and without any actual functionality. What a fun guy. I managed to get the [source](https://files.actf.co/ffd37383709a2617e404add43fce7fafc68d03dbe4804b95a43e4ad6308bd6bb/library_in_c.c) and a copy of [libc](https://files.actf.co/74ca69ada4429ae5fce87f7e3addb56f1b53964599e8526244fecd164b3c4b44/libc.so.6) from him as well.
>
> Find it on the shell server at **/problems/2020/library\_in\_c**, or over tcp at **nc shell.actf.co 20201**.

We're given the file library\_in\_c.c, 

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	char name[64];
	char book[64];

	puts("Welcome to the LIBrary in C!");
	puts("What is your name?");
	fgets(name, 64, stdin);
	// printf works just like System.out.print in Java right?
	printf("Why hello there ");
	printf(name);
	puts("And what book would you like to check out?");
	fgets(book, 64, stdin);
	printf("Your cart:\n - ");
	printf(book);
	puts("\nThat's great and all but uh...");
	puts("It turns out this library doesn't actually exist so you'll never get your book.");
	puts("Have a nice day!");
}
```

and a copy of the version of libc running on the server.

As the comment hints, the vulnerability is the insecure use of printf - this is a classic format string vulnerability.

TODO: the rest, ya know  


