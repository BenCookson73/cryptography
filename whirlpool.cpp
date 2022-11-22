#include <iostream>
#include <cmath>
#include <cstring>

using namespace std;

int oddmultiple(int num, int divis){
  if (num%divis) return 0;
  if ((num/divis)%2) return 0;
  return 1;
};


class whirlpool {
  private:
    unsigned int *message;
    unsigned int CState[4][4];
    unsigned int KState[4][4];
    int numblocks=0;

    unsigned int ebox[16]={0x1, 0xb, 0x9, 0xc,0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0}; //e mini box for mix rows
    unsigned int eboxinv[16]={0xf, 0x0, 0xd, 0x7, 0xb, 0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4, 0x8, 0x6}; //e-1 mini box for mix rows
    unsigned int rbox[16]={0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0}; //r mini box for mix rows
    void pad(char *m); //pads the text and copies into message
    void w(); //block cipher w
    void addroundkey();
    void subbytes();
    void shiftcollumns();
    void mixrows();
    unsigned int sbox(unsigned int x); //sbox algorithm for mixrows
  public:
    void hash(char *m); //main hash algorithm
    whirlpool(){ //constructor for whirlpool-- prepares everything
      return;
    };
};

void whirlpool::hash(char *m){
  pad(m);
  for(int block=0; block<numblocks; block++){
    printf("\n------ block %d ------", block+1);
    for(int i=0; i<16; i++){ //copies message into CState
      CState[i/4][i%4] = message[block*16+i];
      printf("\n[%d][%d] = %032b", i/4, i%4, message[block*16+i]);
    }
    printf("\n");
    mixrows();
    for(int i=0; i<16; i++){ //copies message into CState
      printf("\n[%d][%d] = %032b", i/4, i%4, message[block*16+i]);
    }
    printf("\n\n\n");
  }
}

void whirlpool::mixrows(){
  for(int i=0; i<16; i++){
    printf("CState[%d][%d] = %08x   was %08x\n", i/4, i%4, sbox(CState[i/4][i%4]), CState[i/4][i%4]);
    CState[i/4][i%4]=sbox(CState[i/4][i%4]);
  }
}

unsigned int whirlpool::sbox(unsigned int x){
    unsigned int y=0; //value after algorithm
    unsigned int r=0;
    //this is the diffusion layer, using e box, e-1 box and r box
    for (int i=0; i<4; i++){
      r = rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]];
      y ^= ebox[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^ebox[x<<(24-i*8)>>28]]<<(24-8*i+4); //first 4 bits
      y ^= eboxinv[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^eboxinv[x<<(24-i*8+4)>>28]]<<(24-8*i);
      }
    return y;
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
  printf("numblocks=%d   bits=%d  msize=%d\n", numblocks, bits, msize);
  message = new unsigned int[bits+256];//size of padding, plus block for size of origional message
  int i=0, j;
  unsigned int var;
  while (i*4<msize){ //copies the bytes into the message array
    printf("%d\n", i*4);
    var = 0;
    for(j=0; j<4; j++){
      if (4*i+j<msize){
        var ^= m[4*i+j]<<((24-8*j)); //works by shifting bytes to right location then Xoring it
        printf("i=%03d j=%03d  ij=%03d  var=%032b     %c\n", i, j, i*4+j, var, m[i*4+j]);
      }
    };
    i++;
    message[i-1]=var;
    printf("conformation of copying: message[%d] = %032b\n", i-1, message[i-1]);
  };

  printf("end of padding=%032b\n\n", 1<<((32-(((msize%8)*8)%32))-1));
  message[msize/4] ^= 1<<((32-(((msize%8)*8 )%32))-1); //sets the end of the message to a 1 bit


  message[(bits+256)/(4*4)-1] = msize; //set the last 256 bits to the size
  printf("bits=%d  (bits+256)/4=%d\n", bits, (bits+256)/(4*4)-1);
  for (int i=0; i<(bits+256)/4; i+=4){
    printf("bits %03d-%03d  bytes %03d-%03d = %032b\n", i, i+3, i/4, i/4+1, message[i/4]);
  }
}; //working i think


int main(int argc, char *argv[]){
  whirlpool instance;

  instance.hash(argv[1]);
  return 0;
}
