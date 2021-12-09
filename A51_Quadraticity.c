#include <stdio.h>
#include<conio.h>
#include<math.h>
#include<stdlib.h>

int total_maxterms=0;

/* A5/1 has 64 bit private key.
   All possible keys are are stored in the below 2D array to perform cube attack i.e.,
   10000000000..0(64 bits),
   01000000000..0, 
   ...,
   00000000000001 
*/	
unsigned char secret_key[64][8] = {	{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
							{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};

//A5/1 algorithm working has taken from internet

int length=0;
/* Masks for the three shift registers */
#define R1MASK	0x07FFFF /* 19 bits, numbered 0..18 */
#define R2MASK	0x3FFFFF /* 22 bits, numbered 0..21 */
#define R3MASK	0x7FFFFF /* 23 bits, numbered 0..22 */

/* Middle bit of each of the three shift registers, for clock control */
#define R1MID	0x000100 /* bit 8 */
#define R2MID	0x000400 /* bit 10 */
#define R3MID	0x000400 /* bit 10 */

/* Feedback taps, for clocking the shift registers.
 * These correspond to the primitive polynomials
 * x^19 + x^5 + x^2 + x + 1, x^22 + x + 1,
 * and x^23 + x^15 + x^2 + x + 1. */
#define R1TAPS	0x072000 /* bits 18,17,16,13 */
#define R2TAPS	0x300000 /* bits 21,20 */
#define R3TAPS	0x700080 /* bits 22,21,20,7 */

/* Output taps, for output generation */
#define R1OUT	0x040000 /* bit 18 (the high bit) */
#define R2OUT	0x200000 /* bit 21 (the high bit) */
#define R3OUT	0x400000 /* bit 22 (the high bit) */

typedef unsigned char byte;
typedef unsigned long word;
typedef word bit;

/* Calculate the parity of a 32-bit word, i.e. the sum of its bits modulo 2 */
bit parity(word x) {
	x ^= x>>16;
	x ^= x>>8;
	x ^= x>>4;
	x ^= x>>2;
	x ^= x>>1;
	return x&1;
}

/* Clock one shift register */
word clockone(word reg, word mask, word taps) {
	word t = reg & taps;
	reg = (reg << 1) & mask;
	reg |= parity(t);
	return reg;
}

/* The three shift registers.  They're in global variables to make the code
 * easier to understand.
 * A better implementation would not use global variables. */
word R1, R2, R3;

/* Look at the middle bits of R1,R2,R3, take a vote, and
 * return the majority value of those 3 bits. */
bit majority() {
	int sum;
	sum = parity(R1&R1MID) + parity(R2&R2MID) + parity(R3&R3MID);
	if (sum >= 2)
		return 1;
	else
		return 0;
}

/* Clock two or three of R1,R2,R3, with clock control
 * according to their middle bits.
 * Specifically, we clock Ri whenever Ri's middle bit
 * agrees with the majority value of the three middle bits.*/
void clock2() {
	bit maj = majority();
	if (((R1&R1MID)!=0) == maj)
		R1 = clockone(R1, R1MASK, R1TAPS);
	if (((R2&R2MID)!=0) == maj)
		R2 = clockone(R2, R2MASK, R2TAPS);
	if (((R3&R3MID)!=0) == maj)
		R3 = clockone(R3, R3MASK, R3TAPS);
}

/* Clock all three of R1,R2,R3, ignoring their middle bits.
 * This is only used for key setup. */
void clockallthree() {
	R1 = clockone(R1, R1MASK, R1TAPS);
	R2 = clockone(R2, R2MASK, R2TAPS);
	R3 = clockone(R3, R3MASK, R3TAPS);
}

/* Generate an output bit from the current state.
 * You grab a bit from each register via the output generation taps;
 * then you XOR the resulting three bits. */
bit getbit() {
	return parity(R1&R1OUT)^parity(R2&R2OUT)^parity(R3&R3OUT);
}

/* Do the A5/1 key setup.  This routine accepts a 64-bit key and
 * a 22-bit frame number. */
void keysetup(byte key[8], word frame, int r)
{
	int i;
	bit keybit, framebit;

	/* Zero out the shift registers. */
	R1 = R2 = R3 = 0;

	/* Load the key into the shift registers,
	 * LSB of first byte of key array first,
	 * clocking each register once for every
	 * key bit loaded.  (The usual clock
	 * control rule is temporarily disabled.) */
	for (i=0; i<64; i++) {
		clockallthree(); /* always clock */
		keybit = (key[i/8] >> (i&7)) & 1; /* The i-th bit of the key */
		R1 ^= keybit; R2 ^= keybit; R3 ^= keybit;
	}

	/* Load the frame number into the shift
	 * registers, LSB first,
	 * clocking each register once for every
	 * key bit loaded.  (The usual clock
	 * control rule is still disabled.) */
	for (i=0; i<22; i++) {
		clockallthree(); /* always clock */
		framebit = (frame >> i) & 1; /* The i-th bit of the frame # */
		R1 ^= framebit; R2 ^= framebit; R3 ^= framebit;
	}

	/* Run the shift registers for 100 clocks
	 * to mix the keying material and frame number
	 * together with output generation disabled,
	 * so that there is sufficient avalanche.
	 * We re-enable the majority-based clock control
	 * rule from now on. */
	for (i=0; i<r; i++) {
		clock2();
	}

	/* Now the key is properly set up. */
}
	
/* Generate output.  We generate 228 bits of
 * keystream output.  The first 114 bits is for
 * the A->B frame; the next 114 bits is for the
 * B->A frame.  You allocate a 15-byte buffer
 * for each direction, and this function fills
 * it in. */

void run(byte AtoBkeystream[], int out)
{
	int i;
	/* Zero out the output buffers. */
	for (i=0; i<=(out-1)/8; i++)		// Pehlay 113/8 tha
		AtoBkeystream[i] = 0;
	
	/* Generate 114 bits of keystream for the
	 * A->B direction.  Store it, MSB first. */
	for (i=0; i<out; i++)		//Max value = 228 for out
	{
		clock2();
		AtoBkeystream[i/8] |= getbit() << (7-(i&7));
	}
}

int encrypt(unsigned long frame, unsigned char *key, int r, int out)
{
	byte AtoB[15];
	int i,w,rem;
	
	keysetup(key, frame, r);
	run(AtoB, out);
	
	w=out/8;							// Returning the required output bit.
	rem=out%8;
	AtoB[w]=AtoB[w]<<(rem-1);
	AtoB[w]&=0x80;

	if (AtoB[w]==0x80)
		return 1;
	else
		return 0;

}


/* Precomputation and online  attack are performed in this function
   1) Precomputation: finding Maxterms on the public input bits that
                      expose superpolys on the secret inputs bits.

      Constant, Linear and Quadraticity properties are tested to consider a term to be a maxterm

   2) Compute the values of each exposed superpoly and solve the equations to recover the secret
      input bits
*/
void cube_attack(int ivpos[], int r, int out)
{
	unsigned long frame = 0x0;
	unsigned int dtob[32768]={0};
	unsigned char iv[32768][24]={0};
	unsigned char plain2[32768][3]={0};
	unsigned char plain[3] = {0x00, 0x00, 0x00};
	unsigned char key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char key0[8]={0}, key1[8]={0},key12[8]={0},key2[8]={0};
	unsigned char key01[8]={0}, key02[8]={0}, key012[8]={0};
	int sum=0,p0=0,p1=0,p2=0,p12=0,z=0,n0=0,n1=0,j=0,k=0,l=0,t=0,row=0,col=0,v=0,T=50;		//T = Number of Quadraticity tests
	int p3=0, p23=0, p13=0, p123=0;
	int num_times_j = 0, num_times_k = 0;
	unsigned char one = 0x01;
	double len=0,base=2;
	unsigned int num=0x0,num2=0x0;
	unsigned char key_quadratic[8] = {0};
	

	len= pow(base,length);		// len=2^length(ivpos)
	
	for (j=0;j<len;j++)
	{
		dtob[j]=num;
		num++;
	}

	for (col=length-1;col>=0;col--)
	{
		for (row=0;row<len;row++)
		{
			iv[row][ivpos[col]-1]=dtob[row]&0x00001;
			dtob[row]=dtob[row]>>1;
		}
	}

	
	num=0x0,num2=0x0;
	for (row=0;row<len;row++)
	{
		for (col=0;col<3;col++)
		{
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num=0x0;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num=0x1;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num=0x2;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num=0x3;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num=0x4;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num=0x5;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num=0x6;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num=0x7;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num=0x8;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num=0x9;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num=0xa;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num=0xb;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num=0xc;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num=0xd;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num=0xe;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num=0xf;
			
			v+=4;

			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num2=0x0;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num2=0x1;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num2=0x2;
			else
			if (iv[row][v]==0 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num2=0x3;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num2=0x4;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num2=0x5;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num2=0x6;
			else
			if (iv[row][v]==0 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num2=0x7;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num2=0x8;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num2=0x9;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num2=0xa;
			else
			if (iv[row][v]==1 && iv[row][v+1]==0 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num2=0xb;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==0)
				num2=0xc;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==0 && iv[row][v+3]==1)
				num2=0xd;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==0)
				num2=0xe;
			else
			if (iv[row][v]==1 && iv[row][v+1]==1 && iv[row][v+2]==1 && iv[row][v+3]==1)
				num2=0xf;
			
			plain2[row][col]=(num*16)+num2;

			v+=4;
		}
		v=0;
	}

	
	for (j=0;j<len;j++)
	{
		frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
		z=encrypt(frame, key, r, out);
		sum^=z;	
	}
	p0=sum;

	if (p0==1)
		n1=n1+1;
	else 
		n0=n0+1;
		
	/* T has to be 2^(64) i.e., every public term needs to be checked for all possible
		private keys to determine if it's a maxterm. For simplicity, T is assumed as 50
		and private keys are selected randomly. 
	  
	*/

	for (t=0;t<T;t++)		//T = Number of Quadraticity tests
	{
		for (k=0;k<8;k++)
		{
			key0[k] = rand()%256;			//srand(k);	//x
			key1[k] = rand()%256;			//x`
			key2[k] = rand()%256;			//x``
		}

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key0, r, out);
			sum^=z;
		}
		p1=sum;

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key1, r, out);
			sum^=z;
		}
		p2=sum;

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key2, r, out);
			sum^=z;
		}
		p3=sum;
		
		for (j=0;j<10;j++)
			key01[j]=key0[j]^key1[j];

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key01, r, out);
			sum^=z;
		}
		p12=sum;

		for (j=0;j<10;j++)
			key12[j]=key1[j]^key2[j];

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key12, r, out);
			sum^=z;
		}
		p23=sum;
		
		for (j=0;j<10;j++)
			key02[j]=key0[j]^key2[j];

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key02, r, out);
			sum^=z;
		}
		p13=sum;
		
		for (j=0;j<10;j++)
			key012[j]=(key0[j]^key1[j])^key2[j];

		sum=0;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key012, r, out);
			sum^=z;
		}
		p123=sum;




		if (p1==1)
			n1=n1+1;
		else 
			n0=n0+1;
        if (p2==1)
			n1=n1+1;
		else
			n0=n0+1;
			
		/* Quadraticity property: 
				p(0) ^ p(x) ^ p(y) ^ p(z) ^ p(x^y) ^ p(y^z) ^ p(x^z) = p(x^y^z)
		*/	
		if ((p0^p1^p2^p3^p12^p13^p23)!=p123)
		{
			printf("Non Quadratic\n");
			break;
		}
	}
	if ((n0==2*T+1) || (n1==2*T+1));
		//printf("Constant\n");
	else if (t==T)
	{
		int re;
		printf("Quadratic ");
		for (j=0;j<length;j++)
			printf("%d ",ivpos[j]);
		printf("\n");
		total_maxterms++;
		printf("\t\t\t\t");				// Displaying Constant Term
		if (p0==1)
			printf("%d,",p0);

		//quadratic terms
		for(j=0;j<64;j++)
		{
			for(k=j+1;k<64;k++)
			{
				for(l=0;l<8;l++){
					key_quadratic[l]=0x00;
				}
							
				num_times_j = 7 - (j%8);
				num_times_k = 7 - (k%8);
	
				key_quadratic[j/8] = key_quadratic[j/8] | (one<<num_times_j);
				key_quadratic[k/8] = key_quadratic[k/8] | (one<<num_times_k);
	
				sum=0;
				for (re=0;re<len;re++)
				{
					frame=plain2[re][0]<<16^plain2[re][1]<<8^plain2[re][2];
					z=encrypt(frame, key_quadratic, r, out);
					sum^=z;
				}
				
				if (p0^sum==1)
					printf("k%dk%d,",j+1,k+1);
					
		   }
			
		}
		
		
		//linear terms
		for (j=0;j<64;j++)
		{
			
			sum=0;
			for (re=0;re<len;re++)
			{
				frame=plain2[re][0]<<16^plain2[re][1]<<8^plain2[re][2];
				z=encrypt(frame, secret_key[j], r, out);
				sum^=z;
			}
			if (p0^sum==1)
				printf("k%d,",j+1);

		}
		printf("\n");
		
		sum=0;						// Online Phase - RHS bits
		key[0] = 0x12;
		key[1] = 0x23;
		key[2] = 0x45;
		key[3] = 0x67;
		key[4] = 0x89;
		key[5] = 0xAB;
		key[6] = 0xCD;
		key[7] = 0xEF;
		for (j=0;j<len;j++)
		{
			frame=plain2[j][0]<<16^plain2[j][1]<<8^plain2[j][2];
			z=encrypt(frame, key, r, out);
			sum^=z;
		}
		p0=sum;
		printf("%d\n",p0);
	}
}


/* This function generates next combination of the term where (size) variables
   are choosen from a set of (total-1) variables.
   Ex: {1,2,3,4,5,6,7},{1,2,3,4,5,6,8},...,{16,17,18,19,20,21,22}, total 22C7 terms
*/
int next_combination(int cube[], int size, int total) {
	int i = size - 1;
	cube[i]++;
	while ((i >= 0) && (cube[i] >= (total) - (size) + 1 + i)) {
		i--;
		cube[i]++;
	}

	if (cube[0] > (total) - (size)) 
		return 0; //All combinations have generated

	for (i = i + 1; i < (size); i++)
		cube[i] = cube[i - 1] + 1;

	return 1;
}


void main()
{
	int total = 23;		// A5/1 has a 22 bit frame number
	int size = 7;		//Cubes of size 7 are considered i.e., p(v1,v2,...,v7,secret key)
	int cube[size];    //it contains 7 sized term which is selected from 22 variables.
	int i,j;
	int rounds=5;
	
	length=size;  

	for(i=0; i<1; i++)		
	{
		printf("Output bit index = %d\n",i+1);

		for (j = 0; j < size; j++)
			cube[j] = j+1;

		cube_attack(cube, rounds, i+1);
		/* Generate and print all the other combinations */
		while (next_combination(cube, size, total)){
				cube_attack(cube, rounds, i+1);
		}
	}

	printf("count : %d",total_maxterms);
	return;
}
