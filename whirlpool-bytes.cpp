#include <iostream>
#include <cmath>
#include <cstring>
#include <cstdint>

typedef uint8_t byte;

int oddmultiple(int num, int divis){
  if (num%divis) return 0; //number is not multiple at allS
  if ((num/divis)%2) return 0;
  return 1;
};

class whirlpool {
  private:
    byte *message;
    byte CState[8][8]; //the plaintext
    byte KState[8][8]; //the key
    byte HState[8][8]; // the hash
    int numblocks=0;

    byte ebox[16]={0x1,0xb,0x9,0xc,0xd,0x6,0xf,0x3,0xe,0x8,0x7,0x4,0xa,0x2,0x5,0x0}; //e mini box for mix rows
    byte eboxinv[16]={0xf,0x0,0xd,0x7,0xb,0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4, 0x8, 0x6}; //e-1 mini box for mix rows
    byte rbox[16]={0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0}; //r mini box for mix rows
    byte TransformationMatrix[8][8] = {
      {1,1,4,1,8,5,2,9},
      {9,1,1,4,1,8,5,2},
      {2,9,1,1,4,1,8,5},
      {5,2,9,1,1,4,1,8},
      {8,5,2,9,1,1,4,1},
      {1,8,5,2,9,1,1,4},
      {4,1,8,5,2,9,1,1},
      {1,4,1,8,5,2,9,1}}; //transformation matrix for mixrows
    void pad(char *m); //pads the text and copies into message
    void w(); //block cipher w
    void addroundkey();
    void addroundconst(int round);
    void addkey();
    void subbytes();
    void shiftcollumns();
    void mixrows();
    byte sbox(unsigned int x); //sbox algorithm for mixrows
  public:
    void hash(char *m, byte IV[16]); //main hash algorithm
    byte digest[64];
    whirlpool(){ //constructor for whirlpool-- prepares everything
      //zero out all states
      for (int i=0; i<64; i++){
        CState[i/8][i%8]=0;
        KState[i/8][i%8]=0;
        HState[i/8][i%8]=0;
      }
      return;
    };
    void printfstates();
    void showhash();
};

void whirlpool::hash(char *m, byte IV[16]){
  pad(m);
  w();
}
void whirlpool::w(){
  //abcdefg
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
      printf("bits are more than 256  %d -> %d\n", bits, bits + (256-bits%256));
      bits+= 256-bits%256; // else add the remainder to bring to closet 256
    }
    printf("bits=%d\n", bits);
  };
  if (oddmultiple(bits, 256)==0){
    printf("bits are not an odd multiple of 256 =  %d", bits);
    bits+=256;
  }
  numblocks = (bits/256)+1; //add one for the final 256 bits
  printf("\nnumblocks = %d   bits=%d", numblocks, bits);

  /**************************************************************************\
  this section is getting copying the message into the message
  \**************************************************************************/
  printf("\nnumblocks=%d   bits=%d  msize=%d\n", numblocks, bits+256, msize);
  message = new byte[bits+256];//size of padding, plus block for size of origional message

  int i=0;
  for(int i=0; i<msize; i++){
    message[i] = (byte) m[i];
    printf("message[%i] = %08b  = %c\n", i, m[i], m[i]);
  }
  //end of padding is (byte) (1<<((int) std::log2(m[msize-1]&-m[msize-1])-1))
  printf("end of padding=%b\n\n", (byte) (1<<((int) std::log2(m[msize-1]&-m[msize-1])-1)));
  if((1<<((int) std::log2(m[msize-1]&-m[msize-1])-1)>=1)){
    message[msize-1] ^= 1<<((int) std::log2(m[msize-1]&-m[msize-1])-1);
  }
  else{
    message[msize] = (byte) 128;
  }
  //sets the end of the message to a 1 bit


  message[(bits+256)/8-1] = msize; //set the last 256 bits to the size
  printf("bits=%d  (bits+256)/8=%d\n", bits, (bits+256)/8-1);
  for (int i=0; i<(bits+256)/8; i++){
    if(i%4==0) printf("\nbytes %03i-%03i\t", i, i+3);
    printf("%08b ", message[i]);
  }
};
void whirlpool::addkey(){
  for (int i=0; i<64; i++){
    CState[i/8][i%8] ^= KState[i/8][i%8];
  }
}

void whirlpool::printfstates(){
  for(int i=0; i<64; i++){ //copies message into CState
    printf("CSate[%d][%d]=%032b\t\tKState[%d][%d]=%032b\t\tHState[%d][%d]=%032b\n",
     i/8, i%8, CState[i/8][i%8], i/8, i%8, KState[i/8][i%8],  i/8, i%8, HState[i/8][i%8]);
  }
}
void whirlpool::showhash(){
  printf("\n\n%s=",message);
  for(int i=0; i<64; i++){
    printf("%08x", HState[i/8][i%8]);
  }
}


int main(int argc, char *argv[]){
  if (argc==1){
    printf("[!!!] error- require command line input for message");
    exit(0);
  }
  printf("argv[1] = %s\n\n\n", argv[1]);
  whirlpool instance;
  byte IV[16] = (byte[16]) {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
  instance.hash(argv[1], IV);
  return 0;
}
