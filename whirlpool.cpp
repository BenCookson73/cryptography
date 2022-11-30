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
    unsigned int CState[4][4]; //the plaintext
    unsigned int KState[4][4]; //the key
    unsigned int HState[4][4]; // the hash
        int numblocks=0;

    unsigned int ebox[16]={0x1, 0xb, 0x9, 0xc,0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0}; //e mini box for mix rows
    unsigned int eboxinv[16]={0xf, 0x0, 0xd, 0x7, 0xb, 0xe, 0x5, 0xa, 0x9, 0x2, 0xc, 0x1, 0x3, 0x4, 0x8, 0x6}; //e-1 mini box for mix rows
    unsigned int rbox[16]={0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0}; //r mini box for mix rows
    unsigned int Cmatrix[8][8] = {
      {1,1,4,1,8,5,2,9}, {9,1,1,4,1,8,5,2}, {2,9,1,1,4,1,8,5}, {5,2,9,1,1,4,1,8},
      {8,5,2,9,1,1,4,1}, {1,8,5,2,9,1,1,4}, {4,1,8,5,2,9,1,1}, {1,4,1,8,5,2,9,1}};
    void pad(char *m); //pads the text and copies into message
    void w(); //block cipher w
    void addroundkey();
    void addkey();
    void subbytes();
    void shiftcollumns();
    void mixrows();
    unsigned int sbox(unsigned int x); //sbox algorithm for mixrows
  public:
    void hash(char *m, unsigned int IV[16]); //main hash algorithm
    void printfstates();
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
  for(int block=0; block<numblocks; block++){
    printf("\n------ block %d ------", block+1);
    for(int i=0; i<16; i++){ //copies message into CState
      CState[i/4][i%4] = message[block*16+i];
    };
    printf("before w() round function\n");
    printfstates();
    w();
    for(int i=0; i<16; i++){ //Xor HState and CState and tKState
      HState[i/4][i%4] ^= CState[i/4][i%4] ^ KState[i/4][i%4];
    }
    printf("after w() round function\n");
    printfstates();
    printf("\n\n\n");
    showhash();
  }
}
void whirlpool::w(){
  addkey();
  subbytes();
  shiftcollumns();
  mixrows();
}

void whirlpool::mixrows(){
  printf("\n\n\n  ----mix rows------\n\n");
  int ProductMatrix[4][4];
  for(int i=0; i<64; i++){ //zero out ProductMatrix
    ProductMatrix[i/16][i%4]=0;
  };
  // matrix multiplication of each byte
  for (int i=0; i<64; i++){
    //multiply with every byte on its row
    for(int j=0; j<8; j++){
      printf("Cmatrix[%02d][%02d] = %02x\t", (j*8+i%8)/8, (j*8+i%8)%8, (Cmatrix[(j*8+i%8)/8][(j*8+i%8)%8]));
      printf("CState[%02d][%02d] byte %02d = %02x\t", ((i-(i%8))+j)/16, ((i-(i%8))+j)%4, (24-(i%4*8)), (CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24));
      printf("Cmatrix*CState = %02x\t", ((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(Cmatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0xFF)); //Xor with 0xFF to get only 8 bytes
      printf("value = %08x\t", (((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(Cmatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0xFF))<<(24-(i%4*8)));

      printf("ProductMatrix[%02d][%02d] = %08x\t", i/16, (i/4)%4, ProductMatrix[i/16][(i/4)%4]);
      printf("ProductMatrix^(Cmatrix*CState) = %08x", ProductMatrix[i/16][(i/4)%4]^(((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(Cmatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0xFF)<<(24-(i%4*8))));

      ProductMatrix[i/16][(i/4)%4] ^= (((CState[((i-(i%8))+j)/16][((i-(i%8))+j)%4]<<(24-(i%4*8))>>24)*(Cmatrix[(j*8+i%8)/8][(j*8+i%8)%8]))%(0xFF))<<(24-(i%4*8));
      printf("\n");
    }
    printf("\n\n");
  }
  for (int i=0; i<64; i++){
    CState[i/16][i%4] = ProductMatrix[i/16][i%4];
  }
}
void whirlpool::shiftcollumns(){
  unsigned int tempCState[64], tempKState[64]; //temporary
  for (int i=0; i<64; i++){
    tempCState[i]=0;
    tempKState[i]=0;
  }
  tempCState[0] = CState[0][0];
  for (int i=0; i<64; i++){
    //(((64-i)*7)%64)
    int loc = (((64-i)*7)%64);
    tempCState[i] = CState[loc/16][loc%4]<<(24-loc%4*8);
    tempKState[i] = KState[loc/16][loc%4]<<(24-loc%4*8);
    printf("\ntemp[%d] = CState[%d][%d]   %d", i, (((64-i)*7)%64)/4, (((64-i)*7)%64)%4, (((64-i)*7)%64));
  }
  for (int i=0; i<16; i++){
    for (int j=0; j<4; j++){
      CState[i/4][i%4]^=tempCState[i*4+j];
      KState[i/4][i%4]^=tempKState[i*4+j];
      printf("\nState[%d][%d]^=temp[%d]\ti=%d\tj=%d", i/4, i%4, i*4+j, i, j);
    }
  }

  printf("\n");
}
void whirlpool::subbytes(){// working
  printf("\n-------substitute bytes-------\n");
  for(int i=0; i<16; i++){
    printf("CState[%d][%d] = %08x\t\tKState[%d][%d] = %08x\t\t", i/4, i%4, CState[i/4][i%4], i/4, i%4, KState[i/4][i%4]);
    CState[i/4][i%4]=sbox(CState[i/4][i%4]);
    KState[i/4][i%4]=sbox(KState[i/4][i%4]);
    printf("CState[%d][%d] = %08x\t\tKState[%d][%d] = %08x\n", i/4, i%4, CState[i/4][i%4], i/4, i%4, KState[i/4][i%4]);
  }
}
void whirlpool::addkey(){// Xors CState with KState
  for (int i=0; i<16; i++){
    CState[i/4][i%4]^=KState[i/4][i%4];
  }
}

unsigned int whirlpool::sbox(unsigned int x){//working
    unsigned int y=0; //value after algorithm
    unsigned int r=0;
    //this is the diffusion layer, using e box, e-1 box and r box
    for (int i=0; i<4; i++){
      r = rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]];
      y ^= ebox[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^ebox[x<<(24-i*8)>>28]]<<(8*i+4);
      y ^= eboxinv[rbox[ebox[x<<(24-i*8)>>28]^eboxinv[x<<(24-i*8+4)>>28]]^eboxinv[x<<(24-i*8+4)>>28]]<<(8*i);
      }
    return y;
}
void whirlpool::pad(char *m){//working i think
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
  };

  printf("end of padding=%032b\n\n", 1<<((32-(((msize%8)*8)%32))-1));
  message[msize/4] ^= 1<<((32-(((msize%8)*8 )%32))-1); //sets the end of the message to a 1 bit


  message[(bits+256)/(4*4)-1] = msize; //set the last 256 bits to the size
  printf("bits=%d  (bits+256)/4=%d\n", bits, (bits+256)/(4*4)-1);
  for (int i=0; i<(bits+256)/4; i+=4){
    printf("bits %03d-%03d  bytes %03d-%03d = %032b\n", i, i+3, i/4, i/4+1, message[i/4]);
  }
};


void whirlpool::printfstates(){
  for(int i=0; i<16; i++){ //copies message into CState
    printf("CSate[%d][%d]=%032b\t\tKState[%d][%d]=%032b\t\tHState[%d][%d]=%032b\n",
     i/4, i%4, CState[i/4][i%4], i/4, i%4, KState[i/4][i%4],  i/4, i%4, HState[i/4][i%4]);
  }
}
void whirlpool::showhash(){
  printf("\n\nhash=");
  for(int i=0; i<16; i++){
    printf("%08x", HState[i/4][i%4]);
  }
}

int main(int argc, char *argv[]){
  whirlpool instance;
  unsigned int IV[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  instance.hash(argv[1], IV);
  return 0;
}
