#include "system_program.h"

/*  A program that prints how many summoned daemons are currently alive */
int execute()
{

   // Create a command that trawl through output of ps -efj and contains "summond"
   char *command = malloc(sizeof(char) * 256);
   sprintf(command, "ps -efj | grep summond  | grep -Ev 'tty|pts' > output.txt");

   int result = system(command);
   if (result == -1)
   {
      printf("Command %s fail to execute. Exiting now. \n", command);
      return 1;
   }

   free(command);

   int live_daemons = 0;
   FILE *fptr;

   /* TASK 7 */
   // 1. Open the file output.txt




   // DO NOT PRINT ANYTHING TO THE OUTPUT

   /***** BEGIN ANSWER HERE *****/

   fptr = fopen("output.txt","r");
   // 2. Fetch line by line using getline()

   size_t buf_size = SHELL_BUFFERSIZE;
    char *line = malloc(sizeof(char) * buf_size); // allocate memory space for the line*


   while(getline(&line, &buf_size, fptr) != -1){
      live_daemons+=1;
   }

   /*********************/
   if (live_daemons == 0)
      printf("No daemon is alive right now.\n");
   else
   {
      printf("Live daemons: %d\n", live_daemons);
   }

   fclose(fptr);

   return 1;
}

int main(int argc, char **args)
{
   return execute();
}