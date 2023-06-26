#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>

#define BASE_DELTA 0x9e3779b9U
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
//TEA 128bit Key 64bit block 
//Why do I make a union?
//The reason is for encrypt and decrypt funtion's argument
typedef union{
	unsigned char ckey[16]; //1*16*8=128
	unsigned int ikey[4]; //4*4*8=128
}convertKeytype;

typedef union{
	unsigned char cblock[8]; //1*8*8=64
	unsigned int iblock[2]; // 4*2*8=64
}convertBlocktype;

convertBlocktype block;
convertBlocktype ecb_header;
convertBlocktype cbc_header;
convertBlocktype IV;
convertBlocktype temp;
convertKeytype pwKey = {0,};
char ecbheader[8] = {'t','e','a','\0','e','c','b','\0'};
char cbcheader[8] = {'t','e','a','\0','c','b','c','\0'};

int encryption = 0;
int decryption = 0;
int modeECB = 0;
int modeCBC = 0;

//TEA algorism 


void encrypt_ (uint32_t* v, uint32_t* k)
{
    uint32_t delta = BASE_DELTA;//, v0 = v[0], v1 = v[1];
    for (int i = 0; i < 32; i++)
    {
        v[0] += (v[1] + delta) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
        v[1] += (v[0] + delta) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
        delta += BASE_DELTA;
    }
    //v[0] = v0; v[1] = v1;
}

void decrypt_ (uint32_t* v, uint32_t* k)
{
    uint32_t delta = 0xC6EF3720;//, v0 = v[0], v1 = v[1];
    for (int i = 0; i < 32; i++)
    {
        v[1] -= (v[0] + delta) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
        v[0] -= (v[1] + delta) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
        delta -= BASE_DELTA;
    }
    //v[0] = v0; v[1] = v1;
}

//TEA algorism

//We have to read a file and put in block like buffer
void encryptFiletoECB(char *filepath,uint32_t *key){
	//Read File
	FILE *fd;
	FILE *newFd;
	
	char name[50];
	fd = fopen(filepath,"rb");
	strcpy(name,filepath);
	strcat(name,".tea");
	newFd = fopen( name ,"wb");
	//fseek(newFd,0,SEEK_SET);

	//Put a ecbheader in ecb Union by char type
	for(int i=0;i<8;i++){
		ecb_header.cblock[i] = ecbheader[i];
	}
	
	encrypt_(ecb_header.iblock, pwKey.ikey);
	
	if(fwrite(&ecb_header,sizeof(ecb_header),1,newFd) == -1)
    {
        perror("Header Write Error");
        exit(-1);
    }
	
//	int offset = 0;
	printf("블록 암호화중...\n");
	printf("================\n");
	while(1){
		for(int i=0;i<8;i++){
			block.cblock[i] =0;
		}
		int length = 0;
		length = (int)fread(&block,sizeof(block),1,fd);
      	if(length == -1)
        {
            perror("Read Error");
            exit(-1);
        }
        if(length == 0)
        {
            break; //EOF
        }
		
//		for(int i=0;i<2;i++){
//			printf("%#x \n", block.iblock[0]);
//		}
		
		encrypt_(block.iblock,pwKey.ikey);
		
//		offset+=8;
//		
//		fseek(newFd,offset,SEEK_SET);
		if(fwrite(&block,sizeof(block),1,newFd) == -1)
        {
            perror("DATA Write Error");
            exit(-1);
        }
	}
	
	int removeFd = fclose(fd);
	fclose(newFd);
	
	if(removeFd ==0){
		remove(filepath);
		printf(".tea파일 생성 후 .pdf파일 삭제 완료\n");
	}else if(removeFd == -1){
			perror("파일삭제 실패\n");
	}
}
	

void decryptFiletoECB(char *filepath,uint32_t *key){
	//Read File
	FILE *fd;
	FILE *newFd;
	
	char name[50]={0,} ;
	fd = fopen(filepath,"rb");
	for(int i=strlen(filepath); i>3 ; i--)
    {
    	if(filepath[i-4] == '.' &&
		filepath[i-3] == 't' &&
		filepath[i-2] == 'e' &&
		filepath[i-1] == 'a'
		){
    		for(int i = 0; i < strlen(filepath) - 4; i++)
   			 {
   			 	name[i]= filepath[i];
    		}
    	    name[strlen(filepath)] = 0;
		}
	}
	newFd = fopen(name,"wb");
	
	int length = 0;
	length = (int)fread(&ecb_header,sizeof(ecb_header),1,fd);
	if(length == -1)
    {
        perror("Header Read Error");
        exit(-1);
    }

	decrypt_(ecb_header.iblock, pwKey.ikey);
	printf("Header Descryption Value\n");
	printf("#tea(null)ecb(null)이면 정상입니다#\n");
	printf("========================\n");
	printf(">>>>>>>%s(null)%s(null)<<<<<<<\n", ecb_header.cblock, ecb_header.cblock + 4);
	if (ecb_header.cblock[0] == 't' &&
        ecb_header.cblock[1] == 'e' &&
        ecb_header.cblock[2] == 'a' &&
        ecb_header.cblock[3] == '\0' &&
        ecb_header.cblock[4] == 'e' &&
        ecb_header.cblock[5] == 'c' &&
        ecb_header.cblock[6] == 'b' &&
        ecb_header.cblock[7] == '\0')
    {
        printf("Header Error 없음\n");
        printf("ECB 복호화 진행\n");
    }
    else
    {
        printf("Header Error 있음\n");
        printf("ECB 복호화 실패\n");
        exit(1);
    }
    
    printf("블록 복호화 중\n");
    printf("==============\n");
	while(1){
		for(int i=0;i<8;i++){
			block.cblock[i] =0;
		}
		int length = 0;
		length = (int)fread(&block,sizeof(block),1,fd);
		if(length == -1)
        {
            perror("Data Read Error");
            exit(-1);
        }
        if(length == 0)
        {
            break; //EOF
        }
	  
//		for(int i=0;i<2;i++){
//			printf("%#x \n", block.iblock[0]);
//		}
		decrypt_(block.iblock,pwKey.ikey);
		
		if(fwrite(&block, sizeof(block),1,newFd) == -1)
    	{
        	perror("Data Write Error");
        	exit(-1);
    	}
        }

	
	fclose(fd);
	int removeFd = fclose(newFd);
	
	if(removeFd ==0){
		remove(filepath);
		printf(".pdf파일 생성 후.tea파일 삭제 완료\n");
	}else if(removeFd == -1){
			perror("파일삭제 실패\n");
	}
}

void encryptFiletoCBC(char *filepath,uint32_t *key){
	//Read File
	FILE *fd;
	FILE *newFd;
	
	char name[50];
	fd = fopen(filepath,"rb");
	strcpy(name,filepath);
	strcat(name,".tea");
	newFd = fopen( name ,"wb");
	
	//Making IV
	srand((unsigned int)time(NULL));
	for (int i = 0; i< 8;i++){
		IV.cblock[i] = rand() % 0x100;
	}
	
	if(fwrite(&IV,sizeof(IV),1,newFd) == -1)
    {
        perror("IV Write Error");
        exit(-1);
    }
	
	//Put a cbcheader in ecb Union by char type
	for(int i=0;i<8;i++){
		cbc_header.cblock[i] = cbcheader[i];
	}
	
	encrypt_(cbc_header.iblock, pwKey.ikey);
	
	if(fwrite(&cbc_header,sizeof(cbc_header),1,newFd) == -1)
    {
        perror("Header Write Error");
        exit(-1);
    }
	
	printf("블록 암호화중...\n");
	printf("================\n");
	while(1){
		for(int i=0;i<8;i++){
			block.cblock[i] =0;
		}
		int length = 0;
		length = (int)fread(&block,sizeof(block),1,fd);
      	if(length == -1)
        {
            perror("Read Error");
            exit(-1);
        }
        if(length == 0)
        {
            break; //EOF
        }
        
        for(int j=0;j<2;j++){
        	block.iblock[j] = IV.iblock[j] ^ block.iblock[j];
        //	printf("%#x \n", block.iblock[j]);
		}
		
		encrypt_(block.iblock,pwKey.ikey);

		if(fwrite(&block,sizeof(block),1,newFd) == -1)
        {
            perror("DATA Write Error");
            exit(-1);
        }
        
        for(int j=0;j<2;j++){
        	IV.iblock[j] = block.iblock[j];
		}
	}
	
	int removeFd = fclose(fd);
	fclose(newFd);
	
	if(removeFd ==0){
		remove(filepath);
		printf(".tea파일 생성 후 .pdf 파일 삭제 완료\n");
	}else if(removeFd == -1){
			perror("파일삭제 실패\n");
	}
}

void decryptFiletoCBC(char *filepath,uint32_t *key){
	//Read File
	FILE *fd;
	FILE *newFd;
	
	char name[50]={0,} ;
	fd = fopen(filepath,"rb");
	for(int i=strlen(filepath); i>3 ; i--)
    {
    	if(filepath[i-4] == '.' &&
		filepath[i-3] == 't' &&
		filepath[i-2] == 'e' &&
		filepath[i-1] == 'a'
		){
    		for(int i = 0; i < strlen(filepath) - 4; i++)
   			 {
   			 	name[i]= filepath[i];
    		}
    	    name[strlen(filepath)] = 0;
		}
	}
	newFd = fopen(name,"wb");
	
	int length = 0;
	length = (int)fread(&IV,sizeof(IV),1,fd);
	if(length == -1)
    {
        perror("IV Read Error");
        exit(-1);
    }
    
    length = (int)fread(&cbc_header,sizeof(cbc_header),1,fd);
	if(length == -1)
    {
        perror("Header Read Error");
        exit(-1);
    }

	decrypt_(cbc_header.iblock, pwKey.ikey);
	printf("Header Descryption Value\n");
	printf("#tea(null)cbc(null)이면 정상입니다#\n");
	printf("========================\n");
	printf(">>>>>>>%s(null)%s(null)<<<<<<<\n", cbc_header.cblock, cbc_header.cblock + 4);
	if (cbc_header.cblock[0] == 't' &&
        cbc_header.cblock[1] == 'e' &&
        cbc_header.cblock[2] == 'a' &&
        cbc_header.cblock[3] == '\0' &&
        cbc_header.cblock[4] == 'c' &&
        cbc_header.cblock[5] == 'b' &&
        cbc_header.cblock[6] == 'c' &&
        cbc_header.cblock[7] == '\0')
    {
        printf("Header Error 없음\n");
        printf("CBC 복호화 진행\n");
    }
    else
    {
        printf("Header Error 있음\n");
        printf("CBC 복호화 실패\n");
        exit(1);
    }
    
    printf("블록 복호화 중\n");
    printf("==============\n");
	while(1){
		for(int i=0;i<8;i++){
			block.cblock[i] =0;
		}
		int length = 0;
		length = (int)fread(&block,sizeof(block),1,fd);
		if(length == -1)
        {
            perror("Data Read Error");
            exit(-1);
        }
        if(length == 0)
        {
            break; //EOF
        }
        
		for(int j=0;j<2;j++){
//			printf("%#x \n", block.iblock[j]);
			temp.iblock[j] = block.iblock[j];
		}        
	  
		decrypt_(block.iblock,pwKey.ikey);
		
		for(int j=0;j<2;j++){
			block.iblock[j] = IV.iblock[j] ^ block.iblock[j];
		}

		if(fwrite(&block, sizeof(block),1,newFd) == -1)
    	{
        	perror("Data Write Error");
        	exit(-1);
    	}
	   	
		for(int j=0;j<2;j++){
			IV.iblock[j] = temp.iblock[j];
		}       	
    }

	fclose(fd);
	int removeFd = fclose(newFd);
	
	if(removeFd ==0){
		remove(filepath);
		printf(".pdf파일 생성 후 .tea파일 삭제 완료\n");
	}else if(removeFd == -1){
			perror("파일삭제 실패\n");
	}
}

void use(void){
	    printf("아래처럼 입력하여 주십시오.\n");
        printf("./tea [-e/-d] [ecb/cbc] 파일이름.확장자");
}


void parseCommandLine(int argc, char *argv[])
{
    if (argc < 4)
    {
        use();
        exit(EXIT_FAILURE);
    }
    
    if(!strcmp(argv[1], "-e"))                              // encrypt
    {
        encryption = 1;
    }
    else if (!strcmp(argv[1], "-d"))                        // decrypt
    {
        decryption = 1;
    }
    else
    {
        use();
    }
    
    if (!strcmp(argv[2], "ecb"))                            // ecb mode
    {
        modeECB = 1;
    }
    else if (!strcmp(argv[2], "cbc"))                     // cbc mode
    {
        modeCBC = 1;
    }
    else
    {
        use();
    }
}

int main(int argc, char *argv[]){
	
	printf("사용자의 (키=비밀번호)를 입력하세요(10자 이상) : ");
	scanf("%s",pwKey.ckey);
	argc = 4;
	
    for (int i = 0; i < 16; i++)                    // 16 char to 4 int
    {
    	pwKey.ckey[i] = pwKey.ckey[i];
	}
	
	parseCommandLine(argc, argv);
	
	if (encryption)
    {
        if (modeECB)
        {
            printf("ECB Encrytion\n");
            encryptFiletoECB(argv[3], pwKey.ikey);
        }
        else if (modeCBC)
        {
            printf("CBC Encryption\n");
            encryptFiletoCBC(argv[3], pwKey.ikey);
        }
        else
        {
            use();
        }
    }
    else if (decryption)
    {
        if (modeECB)
        {
            printf("ECB Decryption\n");
            decryptFiletoECB(argv[3], pwKey.ikey);
        }
        else if (modeCBC)
        {
            printf("CBC Decryption\n");
            decryptFiletoCBC(argv[3], pwKey.ikey);
        }
    }
    else
	{
		use();
	}
	
    return 0;
}
