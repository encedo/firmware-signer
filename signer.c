#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ED25519/sha512.h"
#include "ED25519/ed25519.h"

/*
To build:
1. download ED25519 code from https://github.com/encedo/ed25519 or https://github.com/orlp/ed25519 to folder ED25519
2. compile gcc signer.c ED25519/*.c -o signer.exe


signer.exe -i Encedo_FW_v1.hex -b out.bin -o out.hex -S efab5b0739a834bac702aeb5cd08ffe227908faaae501f910e7e07d8d41fbb06

*/



void print_help(void);
static int hex2bin(unsigned char *obuf, const char *ibuf, int len);
unsigned char *ihex2bin_buf(unsigned int *start_address, int *dst_len, FILE *inFile);
int bin2ihex_buf(unsigned char *src, int src_len, unsigned int start_address, FILE *outFile);

//efab5b0739a834bac702aeb5cd08ffe227908faaae501f910e7e07d8d41fbb06 
int main (int argc, char **argv) {
  int i, c;
  char *inhex_fn = NULL, *outbin_fn = NULL, *outhex_fn = NULL;
  FILE *inFile, *outFile;
  int verify_infile = 0;
  
  unsigned int target_start_address;
  int target_len;
  unsigned char *target_bin = NULL;

  unsigned char hash_buf[64];
	unsigned char *ed25519_secret = NULL;
	
  unsigned char public_key[32], private_key[64], signature[64];

  opterr = 0;
  while ((c = getopt (argc, argv, "hVi:o:b:S:")) != -1) {
    switch (c) {
      case 'V':   
        verify_infile = 1;
        break;
      case 'S':   //ED25519 secret (signing key), hex
        ed25519_secret = optarg; 
        break;        
      case 'i':   
        inhex_fn = optarg; //input HEX file name
        break;
      case 'o':   //output HEX file name
        outhex_fn = optarg;
        break;
      case 'b':   //output BIN file name
        outbin_fn = optarg;
        break;
      case 'h':
        print_help();
        return 0;
        break;
      case '?':
        fprintf (stderr, "Parameter(s) parsing  failed!\n");
        return 1;
      default:
        break;
    }
  }
  
  if (!inhex_fn) {
    fprintf (stderr, "No input file specifed.\n");
    return 0;
  }

  if (!verify_infile) {
    if (!outhex_fn) {
      fprintf (stderr, "No output file specifed.\n");
      return 0;
    }

    if (!ed25519_secret) {
      fprintf (stderr, "No ED25519 'secret' provided.\n");
      return 0;
    }
  }

  if (ed25519_secret) {
    c = hex2bin(ed25519_secret, ed25519_secret, strlen(ed25519_secret));
    if (c != 32) {
      fprintf (stderr, "ED25519 'secret' have to be 32bytes long.\n");
      return 0;
    }    
    ed25519_create_keypair(public_key, private_key, ed25519_secret);
  }
  
  inFile = fopen ( inhex_fn, "r");  
  target_bin = ihex2bin_buf(&target_start_address, &target_len, inFile);
  fclose (inFile);
  
  if (target_bin && (target_len > 0)) {
  
    if (ed25519_secret) {
        c = sha512(target_bin, target_len-sizeof(signature), hash_buf);   
        
        //v2
        ed25519_sign(signature, target_bin, target_len-sizeof(signature), public_key, private_key);
        
        //add to target
        memmove(target_bin + (target_len - sizeof(signature) - sizeof(public_key)), public_key, sizeof(public_key));
        memmove(target_bin + (target_len - sizeof(signature) ), signature, sizeof(signature));
    }        
    
    if (verify_infile) {
        unsigned char *public_key_verif, *signatureverif;
        
        public_key_verif = target_bin + (target_len - sizeof(signature) - sizeof(public_key));
        signatureverif = target_bin + (target_len - sizeof(signature));


        printf("Signing PublicKey: ");    
        for(c=0; c<32; c++) {
            printf("%02x", (unsigned char)public_key_verif[c]);
        }
        printf("\r\n");
        
        printf("Target Signature: ");    
        for(c=0; c<64; c++) {
            printf("%02x", (unsigned char)signatureverif[c]);
        }
        printf("\r\n");                
         
        //v2
        c = ed25519_verify(signatureverif, target_bin, target_len-sizeof(signature), public_key_verif);
        if (c) printf ("Signature: OK\r\n");
          else printf ("Signature: FAILED\r\n");
        return 0;
    }
    
    if (outbin_fn) {
      outFile = fopen (outbin_fn, "wb");
      c = fwrite (target_bin, target_len, 1, outFile);
      fclose(outFile);
      if (c != 1) {
        printf ("error: write to output bin file\n");
      }
    }
    
    if (outhex_fn) {
      outFile = fopen (outhex_fn, "wb");      
      c = bin2ihex_buf(target_bin, target_len, target_start_address, outFile);      
      fclose(outFile);
      if (c != 1) {
        printf ("error: write to output hex file\n");
      }
    }
    
    printf("Target Start Address: 0x%08x\r\n", target_start_address);
    printf("Target Length: %ub\r\n", target_len);
    
    printf("Target SHA512: ");    
    for(c=0; c<64; c++) {
      printf("%02x", (unsigned char)hash_buf[c]);
    }
    printf("\r\n");    
               
    printf("Signing PublicKey: ");    
    for(c=0; c<32; c++) {
        printf("%02x", (unsigned char)public_key[c]);
    }
    printf("\r\n");
    
    printf("Target Signature: ");    
    for(c=0; c<64; c++) {
        printf("%02x", (unsigned char)signature[c]);
    }
    printf("\r\n");                
    printf("Done.\r\n");
      
   
  } else {
    printf ("error: processing input file\n");
  }
  
  return 0;
}

void print_help(void) {
  printf("Encedo Firmware Signer version 1.0\r\n");
  printf("(c) Encedo Limited 2019\r\n");
	printf("Options:\r\n");
	printf("-h        - help\r\n");
	printf("-i        - input Intel HEX file name\r\n");
	printf("-o        - output HEX file name\r\n");
	printf("-S        - ED25519 'secret'\r\n");
	printf("-V        - verify input file signature\r\n");
	printf("Example: signer -i infile.hex -i outfile.hex -S 40803E...FEAB01\r\n");
}


static int hex2bin(unsigned char *obuf, const char *ibuf, int len) {
    unsigned char c, c2;

		len = len / 2;
    while (*ibuf != 0) {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            return -1;

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            return -1;

        *obuf++ = ( c << 4 ) | c2;
    }
    return len;
}


static int check_checksum(unsigned char *inbuf, int len) {
    unsigned int check = 0;
    while(len--) {
      check += *inbuf++;
    }
    return check & 0xFF;
}

// more details: http://en.wikipedia.org/wiki/Intel_HEX
unsigned char *ihex2bin_buf(unsigned int *start_address, int *dst_len, FILE *inFile) {
  unsigned int  lines = 0, total = 0, oneline_len, elar = 0, pos, cnt;
  unsigned char oneline [512], raw[256], start_set = 0, *dst = NULL;
  
  *dst_len = 1024*1024;
  dst = malloc(*dst_len);                                                         //allocate 1mB of memory for bin data buffer
  if (dst == NULL) {
      *dst_len = -2; 
      return NULL;
  }
  
  *start_address = 0;
  while ( fgets (oneline, sizeof(oneline), inFile) != NULL ) {
    if (oneline[0] == ':') {                                                      //is valid record?
      oneline_len = strlen(oneline)-2;                                            //get line length
      hex2bin(raw, oneline+1, oneline_len);                                       //convert to bin
      if (check_checksum(raw, oneline_len/2) == 0) {                              //check cheksum validity
        if ((raw[0] == 2) && (raw[1] == 0) && (raw[2] == 0) && (raw[3] == 4)) {   //> Extended Linear Address Record  :020000040803EF
          elar = (unsigned int)raw[4]<<24 | (unsigned int) raw[5]<<16;              //gen new address offset
        } else
        if ((raw[0] == 0) && (raw[1] == 0) && (raw[2] == 0) && (raw[3] == 1)) {   //>End Of File record   :00000001FF
          *dst_len = total;                                                       //return total size of bin data && start address
          return dst;
        } else
        if (raw[3] == 0) {                                                        //>Data record - process
          pos = elar + ( (unsigned int)raw[1]<<8 | (unsigned int)raw[2] );          //get start address of this chunk
          if (start_set==0) {
            *start_address = pos;                                                     //set it as new start addres - only possible for first data record
            start_set = 1;                                                             //only once - this is start address of thye binary data
          }
          pos -= *start_address;
          cnt = raw[0];                                                                //get chunk size/length
          if (pos+cnt > *dst_len) {                                                    //enlarge buffer if required
              unsigned char *dst_new = realloc(dst, *dst_len + 8192);                //add 8kB of new space
              if (dst_new == NULL) {
                *dst_len = -2;                                                         //allocation error - exit
                free(dst);
                return NULL;              
              } else {
                *dst_len += 8192;
                dst = dst_new;                                                         //allocation succesed - copy new pointer
              }
          }
          memmove(dst+pos, raw+4, cnt);
          if (pos+cnt > total) {                                                       //set new total variable
            total = pos+cnt;                                                           //tricky way - file can be none linear!
          }
        }
      } else {
        *dst_len = -1;                                                             //checksum error - exit
        return NULL;
      }
    }
    lines++;                                                                       //not a IntelHex line - comment?
  }
  *dst_len = -3;                                                                   //fatal error - no valid intel hex file processed
  free(dst);
  return NULL;
}



static int bin2ihex(char *obuf, const unsigned char *ibuf, int len) {
    int ret = len /2;

    *obuf = ':';
    while(len--) {
      sprintf(obuf+strlen(obuf), "%02X", *ibuf++);
    }
    sprintf(obuf+strlen(obuf), "\r\n");
    
    return ret;
}


static int calc_checksum(unsigned char *inbuf, int len) {
    unsigned char check = 0;
    while(len--) {
      check += *inbuf++;
    }
    return 0 - check;
}


int bin2ihex_buf(unsigned char *src, int src_len, unsigned int start_address, FILE *outFile) {
 int loop64k, rest64k, inner64k, ptr, c, segment, chunk;
 unsigned char buf[64];
 char sbuf[128];
 
 
  if (start_address % 64*1024) {
    return -1;
  }
  segment = start_address >> 16;
  
  loop64k = src_len / (64*1024);
  rest64k = src_len % 64*1024;
  
  ptr = 0;
  while (loop64k--) {
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
    for(inner64k=0; inner64k < (64*1024) / chunk; inner64k++) {
      buf[0] = chunk;
      buf[1] = (inner64k*chunk) >> 8;
      buf[2] = (inner64k*chunk) & 0xff;
      buf[3] = 0;
      memmove(buf+4, src+ptr, chunk);
      buf[4+chunk] = calc_checksum(buf, chunk+4);
      memset(sbuf, 0, sizeof(sbuf));
      c = bin2ihex(sbuf, buf, chunk+5);
      c = fwrite(sbuf, strlen(sbuf), 1, outFile);
      ptr += chunk;
    }
    segment++;
  }
  
  if (rest64k) {  
    buf[0] = 0x02;
    buf[1] = buf[2] = 0;
    buf[3] = 0x04;
    buf[4] = segment >> 8;    
    buf[5] = segment & 0xff;    
    buf[6] = calc_checksum(buf, 6);
    c = bin2ihex(sbuf, buf, 7);
    c = fwrite(sbuf, strlen(sbuf), 1, outFile);

    chunk = 16;
    inner64k = (64*1024) / chunk;
    for(inner64k=0; (64*1024) / chunk; inner64k++) {
      buf[0] = chunk;
      buf[1] = (inner64k*chunk) >> 8;
      buf[2] = (inner64k*chunk) & 0xff;
      buf[3] = 0;
      memmove(buf+4, src+ptr, chunk);
      buf[4+chunk] = calc_checksum(buf, chunk+4);
      memset(sbuf, 0, sizeof(sbuf));
      c = bin2ihex(sbuf, buf, chunk+5);
      c = fwrite(sbuf, strlen(sbuf), 1, outFile);
      ptr += chunk;
    }  
  }

  //TBD :040000050042EA4982

  sprintf(sbuf, ":00000001FF\r\n");
  c = fwrite(sbuf, strlen(sbuf), 1, outFile);
  
  return 1;
}

/*
const unsigned int crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


unsigned int crc32(unsigned int crc, const void *buf, size_t size) {
	const unsigned char *p;

	p = buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

*/

