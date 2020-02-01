#include <stdlib.h>
#include <stdio.h>

#include "mifare.h"

#define MAX_UIDS 10

int main(int argc, char **argv){

  char results[MAX_UIDS][UID_SIZE];
  int results_size;

  printf("STARTING TESTS\n");
  
  results_size = get_uids(results,MAX_UIDS);
  printf("%d\n",results_size);
  for(int i = 0; i < results_size; i++){
    printf("%s", results[i]);
  }

  return EXIT_SUCCESS;

}
