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
    byte sbox(byte x); //sbox algorithm for mixrows
  public:
    template<class mclass, class ivclass>void hash(mclass *m, mclass *IV); //main hash algorithm
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
};

void whirlpool::hash(char *m, byte IV[64]){
  for (int i=0; i<255; i++){
    sbox(i);
  }
  for(int i=0; i<64; i++){ //copies IV into KState
    KState[i/8][i%8] = IV[i];
  };
  pad(m);
  for(int block=0; block<numblocks; block++){ //loop though every block
    for(int i=0; i<64; i++){ //copies message into CState
      CState[i/8][i%8] = message[(block*64)+i];
    };
    w();
    for(int i=0; i<64; i++){ //Xor HState and CState and tKState
      HState[i/8][i%8] ^= CState[i/8][i%8] ^ KState[i/4][i%4];
    }
  }
  for(int i=0; i<64; i++){
    digest[i] = HState[i/8][i%8];
  }
}
void whirlpool::w(){
  for(int round=0; round<10; round++){
    subbytes();
    shiftcollumns();
    mixrows();
    addroundconst(round);
    addkey();
  }
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
  if (oddmultiple(bits, 256)==0){
    bits+=256;
  }
  numblocks = (bits/256)+1; //add one for the final 256 bits

  /**************************************************************************\
  this section is getting copying the message into the message
  \**************************************************************************/
  message = new byte[bits+256];//size of padding, plus block for size of origional message

  int i=0;
  for(int i=0; i<msize; i++){
    message[i] = (byte) m[i];
  }
  //end of padding is (byte) (1<<((int) std::log2(m[msize-1]&-m[msize-1])-1))
  if((1<<((int) std::log2(m[msize-1]&-m[msize-1])-1)>=1)){
    message[msize-1] ^= 1<<((int) std::log2(m[msize-1]&-m[msize-1])-1);
  }
  else{
    message[msize] = (byte) 128;
  }
  //sets the end of the message to a 1 bit


  message[(bits+256)/8-1] = msize; //set the last 256 bits to the size
  for (int i=0; i<(bits+256)/8; i++){
  }
};

void whirlpool::addkey(){
  for (int i=0; i<64; i++){
    CState[i/8][i%8] ^= KState[i/8][i%8];
  }
}
void whirlpool::addroundconst(int round){
  byte RoundConst[8][8]; //round constant for multiplication with key
  for(int i=0; i<64; i++){ //zero out round constant
    RoundConst[i/8][i%8] = 0;
  }
  for(int i=0; i<8; i++){ //calculate round constant
    RoundConst[0][i] = sbox((8*(round)+i));
  }
  for (int i=0; i<64; i++){ //Xor the KSate with the round constant
    KState[i/8][i%8] ^= RoundConst[i/8][i%8];
  }
}

void whirlpool::mixrows(){
  byte ProductCState[8][8];
  byte ProductKState[8][8];
  for(int i=0; i<64; i++){ //zero out ProductCState and ProductKState
    ProductCState[i/8][i%8]=0;
    ProductKState[i/8][i%8]=0;
  };
  // matrix multiplication of each byte
  for (int i=0; i<64; i++){ //matrix multiplication into product matrix
    //multiply with every byte on its row
    for(int j=0; j<8; j++){ //loops through the rows and collumns in the
      //(byte) (Productstate[i/8][i%8]^(CState[i/8][j]*TransformationMatrix[j][i%8]))

      ProductCState[i/8][i%8] ^= TransformationMatrix[j][i%8] * CState[i/8][j];
      ProductKState[i/8][i%8] ^= TransformationMatrix[j][i%8] * KState[i/8][j];
    }
  }
  for (int i=0; i<64; i++){ //copies the product matrixes into the states
    CState[i/8][i%8] = ProductCState[i/8][i%8];
    KState[i/8][i%8] = ProductKState[i/8][i%8];
  }
}
void whirlpool::shiftcollumns(){
  byte tempCState[64], tempKState[64]; //temporary
  for (int i=0; i<64; i++){ //zero out the temporary states
    tempCState[i]=0;
    tempKState[i]=0;
  }
  tempCState[0] = CState[0][0]; //set first value to initial of CState
  tempKState[0] = KState[0][0]; //set first value to initial of KState
  for (int i=1; i<64; i++){ //shifts the collumns
    //(((64-i)*7)%64) is the next location for matrix, for reasons even i don't quite understand
    tempCState[i] = CState[(((64-i)*7)%64)/8][(((64-i)*7)%64)%8];
    tempKState[i] = KState[(((64-i)*7)%64)/8][(((64-i)*7)%64)%8];
  }
  for (int i=0; i<64; i++){ //puts temporrary states into live states
    CState[i/8][i%8] = tempCState[i];
    KState[i/8][i%8] = tempKState[i];
  }

}
void whirlpool::subbytes(){
  for(int i=0; i<64; i++){
    CState[i/8][i%8]=sbox(CState[i/8][i%8]);
    KState[i/8][i%8]=sbox(KState[i/8][i%8]);
  }
}

byte whirlpool::sbox(byte x){
    byte sval=0; //value after algorithm
    //this is the diffusion layer, using e box, e-1 box and r box
    sval ^= ebox[rbox[ebox[x>>4]^eboxinv[x&0xF]]^ebox[x>>4]]<<4; //bits 0-3
    sval ^= eboxinv[rbox[ebox[x>>4]^eboxinv[x&0xF]]^eboxinv[x&0xF]]; //bits 4-7
    return sval;
}


int main(int argc, char *argv[]){
  if (argc==1){
    printf("no digest provided");
    exit(0);
  }
  whirlpool instance;
  printf("hash \"%s\"= ", argv[1]);
  byte IV[64];
  for(int _=0; _<64; _++){
    IV[_] = 0;
  }
  instance.hash(argv[1], IV);
  for(int i=0; i<64; i++){
    printf("%02x", instance.digest[i]);
  }
  return 0;
}
