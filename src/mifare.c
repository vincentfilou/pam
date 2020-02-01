#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include "sqlite3.h"
#include <unistd.h>
#include <nfc/nfc.h>

#include <freefare.h>

#include "mifare.h"

int get_uids(char (*ids)[ID_SIZE], int max_size){

  int error = 0;
  nfc_device *device = NULL;
  FreefareTag *tags = NULL;
  
  nfc_connstring devices[8];
  size_t device_count;
    
  nfc_context *context;
  nfc_init(&context);
  if (context == NULL){
    printf("LOG_CRIT unable to init libnfc\n");
    return 0;
  }

  device_count = nfc_list_devices(context, devices, sizeof(devices) / sizeof(*devices));
  if (device_count <= 0){
    return 0;
  }

  int result_count = 0;
  
  for (size_t d = 0; d < device_count; d++) {
    if (!(device = nfc_open(context, devices[d]))) {
      continue;
    }

    if (!(tags = freefare_get_tags(device))) {
      nfc_close(device);
      return false;
    }

    for (int i = 0; (!error) && tags[i]; i++) {
      char *tag_uid = freefare_get_tag_uid(tags[i]);
      result_count++;
      if(result_count <= max_size){
	strncpy(ids[result_count-1], tag_uid, ID_SIZE);
      }
      
      free(tag_uid);
    }
    freefare_free_tags(tags);
    nfc_close(device);
  }
  nfc_exit(context);
  
  return result_count;
}
