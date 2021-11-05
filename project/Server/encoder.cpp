#include "encoder.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "server.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "stopwatch.h"

#define NUM_PACKETS 8
#define pipe_depth 4
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)

//SHA
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))



//LZW
using namespace std;
long len=0;
long loc=0;
map<string,long> dictionary;
vector <long> result;
#define MAX 100;
  
//variable 
int chunk_num = 0; 
int offset = 0;
unsigned char* file;
int First_Index=0;
int Last_Index=0;



void handle_input(int argc, char* argv[], int* payload_size) {
	int x;
	extern char *optarg;

	while ((x = getopt(argc, argv, ":c:")) != -1) {
		switch (x) {
		case 'c':
			*payload_size = atoi(optarg);
			printf("payload_size is set to %d optarg\n", *payload_size);
			break;
		case ':':
			printf("-%c without parameter\n", optopt);
			break;
		}
	}
}


uint64_t hash_func(unsigned char *input, unsigned int pos_) 
{ 
  int WIN_SIZE = 16; 
  int PRIME = 3; 
  uint64_t hash=0; 
  for(int i=0; i<16; i++){ 
   	hash += ((input[pos+WIN_SIZE-1-i])*(pow(PRIME, i+1))); 
  } 
  return hash; 
} 
  
void cdc(unsigned char *buff, unsigned int buff_size) 
{ 
  int MODULUS = 256; 
  int TARGET = 0; 
  for(int i=16; i < (buff_size-16); i+=1){ 
  	uint64_t hash = hash_func(buff,i); 
  	if((hash%MODULUS) == TARGET){ 
		   Last_Index = i;
           SHA_256(Last_Index-First_Index,);
           chunk_num++; 
		   First_Index=Last_Index+1;
  	} 
  } 
} 


int k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}; 
  
void SHA(unsigned char *buff, unsigned int buff_size, int Y_Start_Idx, int Y_End_Idx) 
{ 
  //initialize eight harsh value 
  long int h0=0x6a09e667; 
  long int h1=0xbb67ae85; 
  long int h2=0x3c6ef372; 
  long int h3=0xa54ff53a;  
  long int h4=0x510e527f; 
  long int h5=0x9b05688c; 
  long int h6=0x1f83d9ab; 
  long int h7=0x5be0cd19; 
   Append the bit ‘1’ to the end of buff 
   Append the bit ‘0’ to the end of buff until it reaches 512 bit  
For each chunk 
	break buff into sixteen 32-bit big-endian words w[0] , w[1], w[2]…w[15] 
	Extend the sixteen 32-bit words into sixty-four 32-bit words: 
	for i from 16 to 63 
    	  s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor(w[i-15] rightshift 3) 
    	  s1= (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor(w[i-2] rightshift 10) 
    	  w[i] = w[i-16] + s0 + w[i-7] + s1 
	Initialize hash value for this chunk: 
	a = h0; 
	b = h1; 
	c = h2; 
	d = h3; 
	e = h4; 
	f = h5; 
	g = h6; 
	h = h7; 
	Main loop: 
	for i from 0 to 63 
           S0 = (a rightrotate 2) xor (a rightrotate 13) xor(a rightrotate 22) 
           maj = (a and b) xor (a and c) xor(b and c) 
    	   t2 = s0 + maj 
    	   s1 = (e rightrotate 6) xor (e rightrotate 11) xor(e rightrotate 25) 
           ch = (e and f) xor ((not e) and g) 
    	   t1 = h + s1 + ch + k[i] + w[i] 
           h = g 
           g = f 
           f = e 
           e = d + t1 
           d = c 
           c = b 
           b = a 
           a = t1 + t2 
	Add this chunk's hash to result so far: 
	h0 = h0 + a 
	h1 = h1 + b 
	h2 = h2 + c 
	h3 = h3 + d 
	h4 = h4 + e 
	h5 = h5 + f 
	h6 = h6 + g 
	h7 = h7 + h 
  
Produce the final hash value (big-endian): 
digest = hash = h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7 
} 



void LZWcode(string a,string s)
{
    //memset(&result,0,sizeof(int));
    string W,K;
    for(long i=0;i<loc;i++)
    {
        string s1;
        s1=s[i];//将单个字符转换为字符串
        dictionary[s1]=i+1;
    }
    W=a[0];
    loc+=1;
    for(int i=0;i<len-1;i++)
    {
        K=a[i+1];
        string firstT=W;
        string secontT=W;
        if(dictionary.count(firstT.append(K))!=0)//map的函数count(n),返回的是map容器中出现n的次数
            W=firstT;
        else
        {
            result.push_back(dictionary[W]);
            dictionary[secontT.append(K)]=loc++;
            W=K;
        }
    }
    if(!W.empty())
        result.push_back(dictionary[W]);
    for(int i=0;i<result.size();i++)
        cout<<result[i];
	//send out table
	//send out message
}



int main(int argc, char* argv[]) {
	stopwatch ethernet_timer;
	unsigned char* input[NUM_PACKETS];
	int writer = 0;
	int done = 0;
	int length = 0;
	int count = 0;
	ESE532_Server server;

	// default is 2k
	int payload_size = PAYLOAD_SIZE;

	// set payload_size if decalred through command line
	handle_input(argc, argv, &payload_size);

	file = (unsigned char*) malloc(sizeof(unsigned char) * 70000000);
	if (file == NULL) {
		printf("help\n");
	}

	for (int i = 0; i < NUM_PACKETS; i++) {
		input[i] = (unsigned char*) malloc(
				sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
		if (input[i] == NULL) {
			std::cout << "aborting " << std::endl;
			return 1;
		}
	}

	server.setup_server(payload_size);

	writer = pipe_depth;
	server.get_packet(input[writer]);

	count++;

	// get packet
	unsigned char* buffer = input[writer];

	// decode
	done = buffer[1] & DONE_BIT_L;
	length = buffer[0] | (buffer[1] << 8);
	length &= ~DONE_BIT_H;
	// printing takes time so be weary of transfer rate
	//printf("length: %d offset %d\n",length,offset);

	// we are just memcpy'ing here, but you should call your
	// top function here.
	memcpy(&file[offset], &buffer[HEADER], length);

	offset += length;
	writer++;

	//last message
	while (!done) {
		// reset ring buffer
		if (writer == NUM_PACKETS) {
			writer = 0;
		}

		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

		count++;

		// get packet
		unsigned char* buffer = input[writer];

		// decode
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;
		//printf("length: %d offset %d\n",length,offset);
		memcpy(&file[offset], &buffer[HEADER], length);

		offset += length;
		writer++;
	}

	// write file to root and you can use diff tool on board
	FILE *outfd = fopen("output_cpu.bin", "wb");
	int bytes_written = fwrite(&file[0], 1, offset, outfd);
	printf("write file with %d\n", bytes_written);
	fclose(outfd);

	for (int i = 0; i < NUM_PACKETS; i++) {
		free(input[i]);
	}

	free(file);
	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_written * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;

	return 0;
}

