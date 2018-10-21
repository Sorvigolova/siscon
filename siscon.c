// Copyright 2011 Ninjas
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sha2.h"





int
main (int argc, char *argv[])
{
  FILE *in = NULL;

  size_t len;

  u8 *data;
  u8 sys_key[0x10], sys_iv[0x10];
  u8 digest[0x10];

  if (argc != 3)
    fail ("usage: siscon [40000001]/[40000002]/[40000003] [BLNK.bin]/[BASE.bin]/[SYST.bin]");

  in = fopen (argv[1], "rb");
  if (in == NULL)
    fail ("Unable to open %s", argv[1]);
  fseek (in, 0, SEEK_END);
  len = ftell (in);
  fseek (in, 0, SEEK_SET);

  data = malloc (len);

  if (fread (data, 1, len, in) != len)
    fail ("Unable to read syscon fw file");

  fclose (in);

  if(key_get_simple("sys-key", sys_key, 0x10) < 0)
    fail ("unable to load sys-key.");
  if(key_get_simple("sys-iv", sys_iv, 0x10) < 0)
    fail ("unable to load sys-iv.");

  aes128cbc (sys_key, sys_iv, data, len, data);
  //sha2 (data + 32, len - 32, digest, 0);

  /*if (memcmp (data, digest, 0x20) != 0)
    fail ("SHA2 mac mismatch");*/

  memcpy_to_file (argv[2], data, len);

  return 0;
}
