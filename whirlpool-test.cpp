#include <iostream>
#include <cmath>
#include <cstring>
#include <sys/time.h>
using namespace std;

int oddmultiple(int num, int divis){
  if (num%divis) return 0;
  if ((num/divis)%2) return 0;
  return 1;
};


class whirlpool {
  private:
    unsigned int *message;
    unsigned int CState[4][4]; //the plaintext
    unsigned int KState[4][4]; //the key
    unsigned int HState[4][4]; // the hash
        int numblocks=0;

    unsigned int ebox[16]={0x1, 0xb, 0x9, 0xc,0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0}; //e mini box for mix rows
    unsigned int eboxinv[16]={0xf, 0x0, 0xd, 0x7, 0xb, 0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4, 0x8, 0x6}; //e-1 mini box for mix rows
    unsigned int rbox[16]={0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0}; //r mini box for mix rows
    unsigned int TransformationMatrix[8][8] = {
      {1,1,4,1,8,5,2,9}, {9,1,1,4,1,8,5,2}, {2,9,1,1,4,1,8,5}, {5,2,9,1,1,4,1,8},
      {8,5,2,9,1,1,4,1}, {1,8,5,2,9,1,1,4}, {4,1,8,5,2,9,1,1}, {1,4,1,8,5,2,9,1}};
    void pad(char *m); //pads the text and copies into message
    void w(); //block cipher w
    void addroundkey();
    void addroundconst(int round);
    void addkey();
    void subbytes();
    void shiftcollumns();
    void mixrows();
    unsigned int sbox(unsigned int x); //sbox algorithm for mixrows
  public:
    void hash(char *m, unsigned int IV[16]); //main hash algorithm
    void showhash();
    whirlpool(){ //constructor for whirlpool-- prepares everything
      //zero out all states
      for (int i=0; i<16; i++){
        CState[i/4][i%4]=0;
        KState[i/4][i%4]=0;
        HState[i/4][i%4]=0;
      }
      return;
    };
};
void whirlpool::hash(char *m, unsigned int IV[16]){
  pad(m);
  for(int i=0; i<16; i++){ //copies IV into KState
    KState[i/4][i%4] = IV[i];
  };
  for(int block=0; block<numblocks; block++){ //loop though every block
    for(int i=0; i<16; i++){ //copies message into CState
      CState[i/4][i%4] = message[block*16+i];
    };
    w();
    for(int i=0; i<16; i++){ //Xor HState and CState and tKState
      HState[i/4][i%4] ^= CState[i/4][i%4] ^ KState[i/4][i%4];
    }
  }
}
void whirlpool::w(){
  addkey();
  for(int i=0; i<10; i++){
    subbytes();
    shiftcollumns();
    mixrows();
    addroundconst(i);
    addkey();
  } //10 rounds
}

void whirlpool::mixrows(){
  int ProductCState[4][4];
  int ProductKState[4][4];
  for(int i=0; i<64; i++){ //zero out ProductCState and ProductKState
    ProductCState[i/16][i%4]=0;
    ProductKState[i/16][i%4]=0;
  };
  // matrix multiplication of each byte
  for (int i=0; i<64; i++){ //matrix multiplication into product matrix
    //multiply with every byte on its row
    for(int j=0; j<8; j++){ //loops through the rows and collumns in th
      ProductCState[i/16][(i/4)%4] ^= (((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(TransformationMatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0x100))<<(24-(i%4*8));
      // ((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24) is the corresponding address in said row, and the corresponding bytes
      // (TransformationMatrix[(j*8+i%8)/8][(j*8+i%8)%8]) is the transformation value on the corresponding collumn
      ProductKState[i/16][(i/4)%4] ^= (((KState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(TransformationMatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0x100))<<(24-(i%4*8));
    }
  }
  for (int i=0; i<64; i++){ //copies the product matrixes into the states
    CState[i/16][i%4] = ProductCState[i/16][i%4];
    KState[i/16][i%4] = ProductKState[i/16][i%4];
  }
}
void whirlpool::shiftcollumns(){
  unsigned int tempCState[64], tempKState[64]; //temporary
  for (int i=0; i<64; i++){ //zero out the temporary states
    tempCState[i]=0;
    tempKState[i]=0;
  }
  tempCState[0] = CState[0][0]; //set first value to initial of CState
  tempKState[0] = KState[0][0]; //set first value to initial of KState
  for (int i=1; i<64; i++){ //shifts the collumns
    //(((64-i)*7)%64) is the next location for matrix, for reasons even i don't quite understand
    tempCState[i] = CState[(((64-i)*7)%64)/16][(((64-i)*7)%64)%4]<<(24-(((64-i)*7)%64)%4*8);
    tempKState[i] = KState[(((64-i)*7)%64)/16][(((64-i)*7)%64)%4]<<(24-(((64-i)*7)%64)%4*8);
  }
  for (int i=0; i<16; i++){ //puts temporrary states into live states
    for (int j=0; j<4; j++){
      CState[i/4][i%4]^=tempCState[i*4+j];
      KState[i/4][i%4]^=tempKState[i*4+j];
    }
  }

}
void whirlpool::subbytes(){
  for(int i=0; i<16; i++){
    CState[i/4][i%4]=sbox(CState[i/4][i%4]);
    KState[i/4][i%4]=sbox(KState[i/4][i%4]);
  }
}
void whirlpool::addkey(){// Xors CState with KState
  for (int i=0; i<16; i++){
    CState[i/4][i%4]^=KState[i/4][i%4];
  }
}
void whirlpool::addroundconst(int round){
  unsigned int RoundConst[4][4]; //round constant for multiplication with key
  for(int i=0; i<16; i++){ //zero out round constant
    RoundConst[i/4][i%4] = 0;
  }
  for(int i=0; i<8; i++){ //calculate round constant
    RoundConst[0][i/4] ^= sbox((8*(round)+i))<<24>>(i%4*8);
  }
  for (int i=0; i<16; i++){ //Xor the KSate with the round constant
    KState[i/4][i%4] ^= RoundConst[i/4][i%4];
  }
}
unsigned int whirlpool::sbox(unsigned int x){
    unsigned int sval=0; //value after algorithm
    //this is the diffusion layer, using e box, e-1 box and r box
    for (int i=0; i<4; i++){ //ngl don't know what to say other than this is the sbox algorithm part
      sval ^= ebox[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^ebox[x<<(24-i*8)>>28]]<<(8*i+4);
      sval ^= eboxinv[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^eboxinv[x<<(24-i*8+4)>>28]]<<(8*i);
      }
    return sval;
}
void whirlpool::pad(char *m){
  int msize = strlen(m);
  int bits=msize*8; //gets number of bits

  /**************************************************************************\
  this section is getting the number of bits including padding and the message
  should result in an odd multiple of 256 as bits
  \**************************************************************************/

  if (oddmultiple(bits, 256)){ //if bits is an odd multiple of 256
    bits+=512;
  }
  if (bits%256){ //if bits are not a multiple of 256
    if (bits<256){
      bits=256; // if it is less than 256, bring to 256, the nearest block
    }
    else{
      bits+= 256-bits%256; // else add the remainder to bring to closet 256
    }
  };
  if ((bits/256)%2==0){
    bits+=256;
  }
  numblocks = (bits/256)+1; //add one for the final 256 bits


  /**************************************************************************\
  this section is getting copying the message into the message
  \**************************************************************************/
  message = new unsigned int[bits+256];//size of padding, plus block for size of origional message
  int i=0, j;
  unsigned int var;
  while (i*4<msize){ //copies the bytes into the message array
    var = 0;
    for(j=0; j<4; j++){
      if (4*i+j<msize){
        var ^= m[4*i+j]<<((24-8*j)); //works by shifting bytes to right location then Xoring it
      }
    };
    i++;
    message[i-1]=var;
  };

  message[msize/4] ^= 1<<((32-(((msize%8)*8 )%32))-1); //sets the end of the message to a 1 bit


  message[(bits+256)/(4*4)-1] = msize; //set the last 256 bits to the size
};

void whirlpool::showhash(){
  printf("hash=");
  for(int i=0; i<16; i++){
    printf("%08x", HState[i/4][i%4]);
  }
}

int main(int argc, char *argv[]){
  if (argc==1){
    printf("[!!!] error- require command line input for message");
    exit(0);
  }
  whirlpool instance;
  unsigned int IV[16]={0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000};
  struct timeval tp;
  gettimeofday(&tp, NULL);
  double start = ((tp.tv_sec * 1000 + tp.tv_usec / 1000)*1.0);
  
  for(int i=0; i<1000; i++){
      instance.hash(argv[1], IV);
  }
  gettimeofday(&tp, NULL);
  double end = ((tp.tv_sec * 1000 + tp.tv_usec / 1000)*1.0)-start;
  printf("\n\n\n####time = %f ####", end/1000.0);
  printf("avg time per hash = %f",(end/1000.0)/1000.0);
  return 0;
}