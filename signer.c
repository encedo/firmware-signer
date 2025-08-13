#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "ED25519/sha512.h"
#include "ED25519/ed25519.h"
#include "ED25519/ge.h"

/*
To build:
1. download ED25519 code from https://github.com/encedo/ed25519 or https://github.com/orlp/ed25519 to folder ED25519
2. compile gcc signer.c ED25519/*.c -o signer.exe


signer.exe -i Encedo_FW_v1.hex -b out.bin -o out.hex -S efab5b0739a834bac702aeb5cd08ffe227908faaae501f910e7e07d8d41fbb06

*/

static void print_help(void);
static int hex2bin(unsigned char *obuf, const char *ibuf, int len);
static unsigned char *ihex2bin_buf(unsigned int *start_address, int *dst_len, FILE *inFile);
static int bin2ihex_buf(unsigned char *src, int src_len, unsigned int start_address, FILE *outFile);

#define SIGNMODE_FILED_OFFSET (64 + 32 + 16 + 35 + 1)
#define TIMESTAMP_FIELD_OFFSET (SIGNMODE_FILED_OFFSET + 4)

int main(int argc, char **argv)
{
  int i, c;
  char *inhex_fn = NULL, *outbin_fn = NULL, *outhex_fn = NULL;
  FILE *inFile, *outFile;
  int verify_infile = 0;

  unsigned int target_start_address;
  int target_len;
  unsigned char *target_bin = NULL;

  unsigned char hash_buf[64];
  unsigned char *ed25519_secret = NULL, *appkey_pub = NULL, *ed25519_prvkey = NULL;

  unsigned char public_key[32], private_key[64], signature[64];

  int mode = 0; // default, old version 0x80 new v2 version of Bootloader

  opterr = 0;
  while ((c = getopt(argc, argv, "hVi:o:b:S:k:m:P:")) != -1)
  {
    switch (c)
    {
    case 'V':
      verify_infile = 1;
      break;
    case 'S': // ED25519 secret to derive keypair
      ed25519_secret = optarg;
      break;
    case 'P': // ED25519 private key
      ed25519_prvkey = optarg;
      break;
    case 'k': // AppKey, hex
      appkey_pub = optarg;
      break;
    case 'i':
      inhex_fn = optarg; // input HEX file name
      break;
    case 'o': // output HEX file name
      outhex_fn = optarg;
      break;
    case 'b': // output BIN file name
      outbin_fn = optarg;
      break;
    case 'm': // singmode
      mode = atoi(optarg);
      break;
    case 'h':
      print_help();
      return 0;
      break;
    case '?':
      fprintf(stderr, "Parameter(s) parsing  failed!\n");
      return 1;
    default:
      break;
    }
  }

  if (!inhex_fn)
  {
    fprintf(stderr, "No input file specifed.\n");
    return 0;
  }

  if (!verify_infile)
  {
    if (!outhex_fn)
    {
      fprintf(stderr, "No output file specifed.\n");
      return 0;
    }

    if (!ed25519_secret && !ed25519_prvkey)
    {
      fprintf(stderr, "No ED25519 'secret' or 'private key' provided.\n");
      return 0;
    }
  }

  //'secret' or 'privatekey' - no both the same time
  if (ed25519_secret)
  {
    c = hex2bin(ed25519_secret, ed25519_secret, strlen(ed25519_secret));
    if (c != 32)
    {
      fprintf(stderr, "ED25519 'secret' have to be 32bytes long.\n");
      return 0;
    }
    ed25519_create_keypair(public_key, private_key, ed25519_secret);
  }
  else if (ed25519_prvkey)
  {
    c = hex2bin(ed25519_prvkey, ed25519_prvkey, strlen(ed25519_prvkey));
    if (c != 32)
    {
      fprintf(stderr, "ED25519 'private key' have to be 32bytes long.\n");
      return 0;
    }
    memmove(private_key, ed25519_prvkey, 32);
    ge_p3 A;

    // derive public key based on given private key
    private_key[0] &= 248; // clamp
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A); // get publickey
  }

  if (appkey_pub)
  {
    c = hex2bin(appkey_pub, appkey_pub, strlen(appkey_pub));
    if (c != 32)
    {
      fprintf(stderr, "AppPubKey have to be 32bytes long.\n");
      return 0;
    }
  }

  inFile = fopen(inhex_fn, "r");
  target_bin = ihex2bin_buf(&target_start_address, &target_len, inFile);
  fclose(inFile);

  if (target_bin && (target_len > 0))
  {

    if (ed25519_secret || ed25519_prvkey)
    {

      // v3
      if (appkey_pub)
      {
        memmove(target_bin + (target_len - 256 + 5 * 4), appkey_pub, 32);
      }

      // v2
      memmove(target_bin + (target_len - sizeof(signature) - sizeof(public_key)), public_key, sizeof(public_key));

      if (mode == 0)
      {
        c = sha512(target_bin, target_len - sizeof(signature), hash_buf);
        ed25519_sign(signature, target_bin, target_len - sizeof(signature), public_key, private_key);
        memmove(target_bin + (target_len - sizeof(signature)), signature, sizeof(signature));
      }
      else if (mode == 0x80)
      {
        target_bin[target_len - SIGNMODE_FILED_OFFSET] = mode;
        unsigned int now = time(NULL);
        printf("Time: 0x%08x\n", now);
        target_bin[target_len - TIMESTAMP_FIELD_OFFSET + 3] = (unsigned char)(now >> 24) & 0xFF;
        target_bin[target_len - TIMESTAMP_FIELD_OFFSET + 2] = (unsigned char)(now >> 16) & 0xFF;
        target_bin[target_len - TIMESTAMP_FIELD_OFFSET + 1] = (unsigned char)(now >> 8) & 0xFF;
        target_bin[target_len - TIMESTAMP_FIELD_OFFSET + 0] = (unsigned char)(now) & 0xFF;

        c = sha512(target_bin, target_len - sizeof(signature), hash_buf);
        ed25519_sign(signature, hash_buf, sizeof(hash_buf), public_key, private_key);
        memmove(target_bin + (target_len - sizeof(signature)), signature, sizeof(signature));
      }
    }
    else

        if (verify_infile)
    {
      unsigned char *public_key_verif, *signatureverif;

      public_key_verif = target_bin + (target_len - sizeof(signature) - sizeof(public_key));
      signatureverif = target_bin + (target_len - sizeof(signature));
      int mode_verify = target_bin[target_len - SIGNMODE_FILED_OFFSET];

      printf("\n\nVerification status:\n");
      printf("Signing PublicKey: ");
      for (c = 0; c < 32; c++)
      {
        printf("%02x", (unsigned char)public_key_verif[c]);
      }
      printf("\r\n");

      printf("Target Signature: ");
      for (c = 0; c < 64; c++)
      {
        printf("%02x", (unsigned char)signatureverif[c]);
      }
      printf("\r\n");

      printf("Signature mode: %u\r\n", mode_verify);
      if (mode_verify == 0)
      {
        c = ed25519_verify(signatureverif, target_bin, target_len - sizeof(signature), public_key_verif);
        if (c)
          printf("Signature: OK\r\n");
        else
          printf("Signature: FAILED\r\n");
      }
      else
      {
        c = sha512(target_bin, target_len - sizeof(signature), hash_buf);
        c = ed25519_verify(signatureverif, hash_buf, sizeof(hash_buf), public_key_verif);
        if (c)
          printf("Signature: OK\r\n");
        else
          printf("Signature: FAILED\r\n");
      }
      return 0;
    }

    if (outbin_fn)
    {
      outFile = fopen(outbin_fn, "wb");
      c = fwrite(target_bin, target_len, 1, outFile);
      fclose(outFile);
      if (c != 1)
      {
        printf("error: write to output bin file\n");
      }
    }

    if (outhex_fn)
    {
      outFile = fopen(outhex_fn, "wb");
      c = bin2ihex_buf(target_bin, target_len, target_start_address, outFile);
      fclose(outFile);
      if (c != 1)
      {
        printf("error: write to output hex file\n");
      }
    }
    printf("\n\nSigning status:\n");

    printf("Target Start Address: 0x%08x\r\n", target_start_address);
    printf("Target Length: %ub\r\n", target_len);

    printf("Target body SHA512: ");
    for (c = 0; c < 64; c++)
    {
      printf("%02x", (unsigned char)hash_buf[c]);
    }
    printf("\r\n");

    printf("Signature mode: %u\r\n", mode);
    printf("Signing PublicKey: ");
    for (c = 0; c < 32; c++)
    {
      printf("%02x", (unsigned char)public_key[c]);
    }
    printf("\r\n");

    printf("Signing PrivateKey: ");
    for (c = 0; c < 32; c++)
    {
      printf("%02x", (unsigned char)private_key[c]);
    }
    printf("\r\n");

    printf("Target Signature: ");
    for (c = 0; c < 64; c++)
    {
      printf("%02x", (unsigned char)signature[c]);
    }
    printf("\r\n");
    printf("Done.\r\n");
  }
  else
  {
    printf("error: processing input file\n");
  }

  return 0;
}

void print_help(void)
{
  printf("Encedo Firmware Signer version 1.2\r\n");
  printf("(c) Encedo Limited 2019-2021\r\n");
  printf("Options:\r\n");
  printf("-h        - help\r\n");
  printf("-i        - input Intel HEX file name\r\n");
  printf("-k        - AppPubKey\r\n");
  printf("-m        - signing mode (0 or 0x80)\r\n");
  printf("-o        - output HEX file name\r\n");
  printf("-S        - ED25519 'secret'\r\n");
  printf("-P        - ED25519 'private key'\r\n");
  printf("-V        - verify input file signature\r\n");
  printf("Example: signer -i infile.hex -o outfile.hex -S 40803E...FEAB01\r\n");
}

static int hex2bin(unsigned char *obuf, const char *ibuf, int len)
{
  unsigned char c, c2;

  len = len / 2;
  while (*ibuf != 0)
  {
    c = *ibuf++;
    if (c >= '0' && c <= '9')
      c -= '0';
    else if (c >= 'a' && c <= 'f')
      c -= 'a' - 10;
    else if (c >= 'A' && c <= 'F')
      c -= 'A' - 10;
    else
      return -1;

    c2 = *ibuf++;
    if (c2 >= '0' && c2 <= '9')
      c2 -= '0';
    else if (c2 >= 'a' && c2 <= 'f')
      c2 -= 'a' - 10;
    else if (c2 >= 'A' && c2 <= 'F')
      c2 -= 'A' - 10;
    else
      return -1;

    *obuf++ = (c << 4) | c2;
  }
  return len;
}

static int check_checksum(unsigned char *inbuf, int len)
{
  unsigned int check = 0;
  while (len--)
  {
    check += *inbuf++;
  }
  return check & 0xFF;
}

// more details: http://en.wikipedia.org/wiki/Intel_HEX
unsigned char *ihex2bin_buf(unsigned int *start_address, int *dst_len, FILE *inFile)
{
  unsigned int lines = 0, total = 0, oneline_len, elar = 0, pos, cnt;
  unsigned char oneline[512], raw[256], start_set = 0, *dst = NULL;

  *dst_len = 1024 * 1024;
  dst = malloc(*dst_len); // allocate 1mB of memory for bin data buffer
  if (dst == NULL)
  {
    *dst_len = -2;
    return NULL;
  }

  *start_address = 0;
  while (fgets(oneline, sizeof(oneline), inFile) != NULL)
  {
    if (oneline[0] == ':')
    {                                         // is valid record?
      oneline_len = strlen(oneline) - 2;      // get line length
      hex2bin(raw, oneline + 1, oneline_len); // convert to bin
      if (check_checksum(raw, oneline_len / 2) == 0)
      { // check cheksum validity
        if ((raw[0] == 2) && (raw[1] == 0) && (raw[2] == 0) && (raw[3] == 4))
        {                                                                 //> Extended Linear Address Record  :020000040803EF
          elar = (unsigned int)raw[4] << 24 | (unsigned int)raw[5] << 16; // gen new address offset
        }
        else if ((raw[0] == 0) && (raw[1] == 0) && (raw[2] == 0) && (raw[3] == 1))
        {                   //>End Of File record   :00000001FF
          *dst_len = total; // return total size of bin data && start address
          return dst;
        }
        else if ((raw[0] == 0) && (raw[1] == 0) && (raw[2] == 0) && (raw[3] == 0x10))
        { // Encedo Special Record - Flash Initialization
          // do nothing here
        }
        else if (raw[3] == 0)
        {                                                                  //>Data record - process
          pos = elar + ((unsigned int)raw[1] << 8 | (unsigned int)raw[2]); // get start address of this chunk
          if (start_set == 0)
          {
            *start_address = pos; // set it as new start addres - only possible for first data record
            start_set = 1;        // only once - this is start address of thye binary data
          }
          pos -= *start_address;
          cnt = raw[0]; // get chunk size/length
          if (pos + cnt > *dst_len)
          {                                                         // enlarge buffer if required
            unsigned char *dst_new = realloc(dst, *dst_len + 8192); // add 8kB of new space
            if (dst_new == NULL)
            {
              *dst_len = -2; // allocation error - exit
              free(dst);
              return NULL;
            }
            else
            {
              *dst_len += 8192;
              dst = dst_new; // allocation succesed - copy new pointer
            }
          }
          memmove(dst + pos, raw + 4, cnt);
          if (pos + cnt > total)
          {                    // set new total variable
            total = pos + cnt; // tricky way - file can be none linear!
          }
        }
      }
      else
      {
        *dst_len = -1; // checksum error - exit
        return NULL;
      }
    }
    lines++; // not a IntelHex line - comment?
  }
  *dst_len = -3; // fatal error - no valid intel hex file processed
  free(dst);
  return NULL;
}

static int bin2ihex(char *obuf, const unsigned char *ibuf, int len)
{
  int ret = len / 2;

  *obuf = ':';
  while (len--)
  {
    sprintf(obuf + strlen(obuf), "%02X", *ibuf++);
  }
  sprintf(obuf + strlen(obuf), "\r\n");

  return ret;
}

static int calc_checksum(unsigned char *inbuf, int len)
{
  unsigned char check = 0;
  while (len--)
  {
    check += *inbuf++;
  }
  return 0 - check;
}

int bin2ihex_buf(unsigned char *src, int src_len, unsigned int start_address, FILE *outFile)
{
  int loop64k, rest64k, inner64k, ptr, c, segment, chunk;
  unsigned char buf[64];
  char sbuf[128];

  if (start_address % 64 * 1024)
  {
    return -1;
  }
  segment = start_address >> 16;

  loop64k = src_len / (64 * 1024);
  rest64k = src_len % 64 * 1024;

  sprintf(sbuf, ":00000010F0\r\n");
  c = fwrite(sbuf, strlen(sbuf), 1, outFile);

  ptr = 0;
  while (loop64k--)
  {
    buf[0] = 0x02;
    buf[1] = buf[2] = 0;
    buf[3] = 0x04;
    buf[4] = segment >> 8;
    buf[5] = segment & 0xff;
    buf[6] = calc_checksum(buf, 6);
    memset(sbuf, 0, sizeof(sbuf));
    c = bin2ihex(sbuf, buf, 7);
    c = fwrite(sbuf, strlen(sbuf), 1, outFile);

    chunk = 16;
    for (inner64k = 0; inner64k < (64 * 1024) / chunk; inner64k++)
    {
      buf[0] = chunk;
      buf[1] = (inner64k * chunk) >> 8;
      buf[2] = (inner64k * chunk) & 0xff;
      buf[3] = 0;
      memmove(buf + 4, src + ptr, chunk);
      buf[4 + chunk] = calc_checksum(buf, chunk + 4);
      memset(sbuf, 0, sizeof(sbuf));
      c = bin2ihex(sbuf, buf, chunk + 5);
      c = fwrite(sbuf, strlen(sbuf), 1, outFile);
      ptr += chunk;
    }
    segment++;
  }

  if (rest64k)
  {
    buf[0] = 0x02;
    buf[1] = buf[2] = 0;
    buf[3] = 0x04;
    buf[4] = segment >> 8;
    buf[5] = segment & 0xff;
    buf[6] = calc_checksum(buf, 6);
    c = bin2ihex(sbuf, buf, 7);
    c = fwrite(sbuf, strlen(sbuf), 1, outFile);

    chunk = 16;
    inner64k = (64 * 1024) / chunk;
    for (inner64k = 0; (64 * 1024) / chunk; inner64k++)
    {
      buf[0] = chunk;
      buf[1] = (inner64k * chunk) >> 8;
      buf[2] = (inner64k * chunk) & 0xff;
      buf[3] = 0;
      memmove(buf + 4, src + ptr, chunk);
      buf[4 + chunk] = calc_checksum(buf, chunk + 4);
      memset(sbuf, 0, sizeof(sbuf));
      c = bin2ihex(sbuf, buf, chunk + 5);
      c = fwrite(sbuf, strlen(sbuf), 1, outFile);
      ptr += chunk;
    }
  }

  // TBD :040000050042EA4982

  sprintf(sbuf, ":00000001FF\r\n");
  c = fwrite(sbuf, strlen(sbuf), 1, outFile);

  return 1;
}
