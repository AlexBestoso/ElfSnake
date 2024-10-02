#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#include "./elfsnake.class.h"

int main(int argc, char *argv[]){
	int cmd = -1;
	if(argc > 1){
		cmd = std::stoi(argv[1]);
	}
	printf("Testing Setup...\n");
	std::string fileName = "/usr/bin/cat";
	ElfSnake es(fileName);
	if(es.error)
		return 1;
	es.printHeader();
		
	printf("\nGetting %d program headers....\n", es.getProgramHeaderCount());
	
	for(int i=0; i<es.getProgramHeaderCount(); i++){
		es.printProgramHeader(i);
	}

	printf("\nGetting %d section headers...\n", es.getSectionHeaderCount());
	for(int i=0; i<es.getSectionHeaderCount(); i++){
		es.printSectionHeader(i, i==0? true : false);
	}

	printf("\n\n");
	if(cmd >= 0){
		printf("Dumping %ld bytes from section %d...\n", (long)es.getSectionDataSize(cmd), cmd);
		uint8_t *rawData = es.getSectionData(cmd);
		for(int i=0; i<es.getSectionDataSize(cmd); i++){
			printf("%c", rawData[i]);
		}
		printf("\n----end dump---\n");
	}
	return 0;
}
