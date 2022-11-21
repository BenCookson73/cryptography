#include <iostream>
#include <cmath>
#include <cstring>

#include <bitset> //not needed


using namespace std;

int oddmultiple(int num, int divis){
  if (num%divis) return 0;
  if ((num/divis)%2) return 0;
  return 1;
};


class whirlpool {
  public:
  unsigned int *message;
  unsigned int CState[4][4];
  unsigned int KState[4][4];
  int numblocks=0;

  void hash(char *m);
  void pad(char *m);
  void w();

  void addroundkey();
  void subbytes();
  void shiftcollumns();
  void mixrows();
};

void whirlpool::hash(char *m){
  pad(m);
  printf("\n\n---------- hash ----------\n\n");
  for (int i=0; i < numblocks*  4; i++){ //smaller than number of bytes in message
    for (int j=0; j<16; j++){ //copies one block into the value CState
      CState[j/4][j%4] = message[i*16+j];
      printf("%032b  i=%03d j=%03d i+j=%03d\n", message[i*16+j], i*16, j, i*16+j);
    }
    printf("\n\n");
  };
}

void whirlpool::pad(char *m){
  printf("\n\n---------- padding ----------\n");
  int msize = strlen(m);
  int bits=msize*8; //gets number of bits
  printf("bits=%d  msize=%d\n", bits, msize);

  /**************************************************************************\
  this section is getting the number of bits including padding and the message
  should result in an odd multiple of 256 as bits
  \**************************************************************************/

  if (oddmultiple(bits, 256)){ //if bits is an odd multiple of 256
    bits+=512;
  }
  if (bits%256){ //if bits are not a multiple of 256
    printf("bits are not a multiple of 256  %d\n", bits);
    if (bits<256){
      printf("bits smaller than 256  %d\n", bits);
      bits=256; // if it is less than 256, bring to 256, the nearest block
    }
    else{
      bits+= 256-bits%256; // else add the remainder to bring to closet 256
      printf("bits are more than 256  %d\n", bits);
    }
    printf("\tbits=%d\n", bits);
  };
  if ((bits/256)%2==0){
    bits+=256;
  }
  numblocks = (bits/256)+1; //add one for the final 256 bits
  printf("numblocks = %d   bits=%d", numblocks, bits);


  /**************************************************************************\
  this section is getting copying the message into the message
  \**************************************************************************/
  /*
  printf("numblocks=%d   bits=%d  msize=%d\n", numblocks, bits, msize);
  message = new unsigned int[bits+256];//size of padding, plus block for size of origional message
  int i=0, j;
  unsigned int var;
  while (i*4<msize){ //copies the bytes into the message array
    var = 0;
    for(j=0; j<4; j++){
      if (4*i+j<msize){
        //printf("i=%03d j=%03d  ij=%03d   %c\n", i, j, i*4+j, m[i*4+j]);
        var ^= m[4*i+j]<<((24-8*j)); //works by shifting bytes to right location then Xoring it
      }
    };
    i++;
    message[i-1]=var;
  };
  printf("msize/4=%03d  Xor value=%032b\n\n", msize/4, 1<<((32-(msize*8/4)%32)+1));
  message[msize/4] ^= 1<<((32-(msize*8/4)%32)+1); //sets the end of the message to a 1 bit
  message[(bits+256)/4-1] = msize; //set the last 256 bits to the size

  printf("bits=%d  (bits+256)/4=%d\n", bits, (bits+256)/4);
  for (int i=0; i<(bits+256)/4; i+=4){
    printf("bytes %03d-%03d = %032b\n", i+1, i+4, message[i]);
  }
  */
};


int main(int argc, char *argv[]){
  whirlpool instance;
  instance.pad(argv[1]);
  return 0;
}
