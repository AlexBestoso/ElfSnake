class ElfEhdr{
	private:
		uint8_t *_fileData = NULL;
		Elf64_Ehdr *header64 = NULL;
                Elf32_Ehdr *header32 = NULL;
	public:
		bool class32 = false;

		Elf64_Ehdr *header_64(void){
			return this->header64;
		}
	
		Elf32_Ehdr *header_32(void){
			return this->header32;
		}

		void *header(void){
			return class32 ? (void*)header32 : (void*)header64;
		}

		void init(uint8_t *fileData){
			this->_fileData = fileData;
			this->header64 = (Elf64_Ehdr*)this->_fileData;
                	this->header32 = (Elf32_Ehdr*)this->_fileData;
			if(header64->e_ident[EI_CLASS] == ELFCLASS32)
                                this->class32 = true;
                        else
                                this->class32 = false;
		}
		
		int identMax(void){
			return EI_NIDENT;
		}
		unsigned char ident(int index){
			return this->class32 ? this->header32->e_ident[index] : this->header64->e_ident[index];
		}
		int type(void){
			return this->class32 ? (int)this->header32->e_type : (int)this->header64->e_type;
		}
              	int machine(void){
			return this->class32 ? (int)this->header32->e_machine : (int)this->header64->e_machine;
		}
		int version(void){
			return this->class32 ? (int)this->header32->e_version : (int)this->header64->e_version;
		}
		int entry(void){
			return this->class32 ? (int)this->header32->e_entry : (int)this->header64->e_entry;
		}
               	int phoff(void){
			return this->class32 ? (int)this->header32->e_phoff : (int)this->header64->e_phoff;
		}
		int shoff(void){
			return this->class32 ? (int)this->header32->e_shoff : (int)this->header64->e_shoff;
		}
		int flags(void){
			return this->class32 ? (int)this->header32->e_flags : (int)this->header64->e_flags;
               	}
		int ehsize(void){
			return this->class32 ? (int)this->header32->e_ehsize : (int)this->header64->e_ehsize;
               	}
               	int phentsize(void){
			return this->class32 ? (int)this->header32->e_phentsize : (int)this->header64->e_phentsize;
		}
              	int phnum(void){
			return this->class32 ? (int)this->header32->e_phnum : (int)this->header64->e_phnum;
		}
               	int shentsize(void){
			return this->class32 ? (int)this->header32->e_shentsize : (int)this->header64->e_shentsize;
		}
               	int shnum(void){
			return this->class32 ? (int)this->header32->e_shnum : (int)this->header64->e_shnum;
		}
               	int shstrndx(void){
			return this->class32 ? (int)this->header32->e_shstrndx : (int)this->header64->e_shstrndx;
		}
};

class ElfShdr{
	private:
		uint8_t *_fileData = NULL;
		Elf64_Shdr *header64 = NULL;
		Elf32_Shdr *header32 = NULL;
	public:
		bool class32 = false;
		int off = 0;
		int sze = 0;
		int index = 0;

		void init(uint8_t *fileData){
                        this->_fileData = fileData;
                        Elf64_Ehdr* test = (Elf64_Ehdr*)this->_fileData;
                        Elf32_Ehdr* test32 = (Elf32_Ehdr*)this->_fileData;
                        if(test->e_ident[EI_CLASS] == ELFCLASS32){
                                this->class32 = true;
                                this->off = (long int)test32->e_shoff;
                                this->sze = (long int)test32->e_shentsize;
                        }else{
                                this->class32 = false;
                                this->off = (long int)test->e_shoff;
                                this->sze = (long int)test->e_shentsize;
                        }


                        this->header64 = (Elf64_Shdr *)&this->_fileData[this->off];
                        this->header32 = (Elf32_Shdr *)&this->_fileData[this->off];
                }

		void setIndex(int idx){
                        this->index = idx;
                        this->header64 = (Elf64_Shdr *)&this->_fileData[this->off+(this->sze*this->index)];
                        this->header32 = (Elf32_Shdr *)&this->_fileData[this->off+(this->sze*this->index)];
                }
		
		int name(void){
			return this->class32 ? (int)this->header32->sh_name : (int)this->header64->sh_name;
		}
		int type(void){
			return this->class32 ? (int)this->header32->sh_type : (int)this->header64->sh_type;
               	}
		int flags(void){
			return this->class32 ? (int)this->header32->sh_flags : (int)this->header64->sh_flags;
		}
		int addr(void){
			return this->class32 ? (int)this->header32->sh_addr : (int)this->header64->sh_addr;
               	}
		int offset(void){
			return this->class32 ? (int)this->header32->sh_offset : (int)this->header64->sh_offset;
               	}
		int size(void){
			return this->class32 ? (int)this->header32->sh_size : (int)this->header64->sh_size;
               	}
		int link(void){
			return this->class32 ? (int)this->header32->sh_link : (int)this->header64->sh_link;
		}
               	int info(void){
			return this->class32 ? (int)this->header32->sh_info : (int)this->header64->sh_info;
		}
               	int addralign(void){
			return this->class32 ? (int)this->header32->sh_addralign : (int)this->header64->sh_addralign;
		}
               	int entsize(void){
			return this->class32 ? (int)this->header32->sh_entsize : (int)this->header64->sh_entsize;
		}
};

class ElfPhdr{
	private:
		uint8_t *_fileData = NULL;
		Elf64_Phdr *header64 = NULL;
		Elf32_Phdr *header32 = NULL;
	public:
		bool class32 = false;
		long int off = 0;
                long int sze = 0;
		int index = 0;

		void init(uint8_t *fileData){
                        this->_fileData = fileData;
                        Elf64_Ehdr* test = (Elf64_Ehdr*)this->_fileData;
                        Elf32_Ehdr* test32 = (Elf32_Ehdr*)this->_fileData;
                        if(test->e_ident[EI_CLASS] == ELFCLASS32){
                                this->class32 = true;
				this->off = (long int)test32->e_phoff;
                        	this->sze = (long int)test32->e_phentsize;
                        }else{
                                this->class32 = false;
				this->off = (long int)test->e_phoff;
                        	this->sze = (long int)test->e_phentsize;
			}


			this->header64 = (Elf64_Phdr *)&this->_fileData[this->off];
			this->header32 = (Elf32_Phdr *)&this->_fileData[this->off];
                }

		void setIndex(int idx){
			this->index = idx;
			this->header64 = (Elf64_Phdr *)&this->_fileData[this->off+(this->sze*this->index)];
			this->header32 = (Elf32_Phdr *)&this->_fileData[this->off+(this->sze*this->index)];
		}
		
		int type(void){
			return this->class32 ? (int)this->header32->p_type : (int)this->header64->p_type;
		}
		int offset(void){
			return this->class32 ? (int)this->header32->p_offset : (int)this->header64->p_type;
		}
               	int vaddr(void){
			return this->class32 ? (int)this->header32->p_vaddr : (int)this->header64->p_vaddr;
		}
               	int paddr(void){
			return this->class32 ? (int)this->header32->p_paddr : (int)this->header64->p_paddr;
		}
               	int filesz(void){
			return this->class32 ? (int)this->header32->p_filesz : (int)this->header64->p_filesz;
		}
               	int memsz(void){
			return this->class32 ? (int)this->header32->p_memsz : (int)this->header64->p_memsz;
		}
               	int flags(void){
			return this->class32 ? (int)this->header32->p_flags : (int)this->header64->p_flags;
		}
		int align(void){
			return this->class32 ? (int)this->header32->p_align : (int)this->header64->p_align;
		}
		
		Elf64_Phdr *header_64(void){
                        return this->header64;
                }

                Elf32_Phdr *header_32(void){
                        return this->header32;
                }

                void *header(void){
                        return class32 ? (void*)header32 : (void*)header64;
                }
};

class ElfSnake{
	private:
		/*
		 * Variables
		 * */

		std::string _fileName = "";
		struct stat _fileStat = {0};
		uint8_t *_fileData = NULL;
		uint8_t *_stringTable = NULL;
		int _fileDescriptor = -1;
		bool class32 = false;

		/*
		 * Functions
		 * */
		int _openFile(std::string f){
			this->_fileName = f;
			int ret = -1;
			if((ret = open(f.c_str(), O_RDWR)) < 0){
                		perror("open");
                		return ret;
        		}
			
			if(fstat(ret, &this->_fileStat) < 0){
                		perror("fstat");
                		close(ret);
				return -1;
        		}

			this->_fileData = (uint8_t *)mmap(NULL, this->_fileStat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, ret, 0);
			if(this->_fileData == MAP_FAILED){
				perror("mmap");
				close(ret);
				return -1;
			}

			return ret;
		}

	public:
		/*
		 * Variables
		 * */
		ElfEhdr ehdr;
		ElfPhdr phdr;
		ElfShdr shdr;
		
		bool error = false;

		/*
		 * Constructor functions
		 * */
		ElfSnake(void){}
		ElfSnake(std::string fileName){
			this->manualInit(fileName);
		}
		
		/*
		 * Initalization / cleanup functions
		 * */
		void manualInit(std::string fileName){
			this->_fileDescriptor = this->_openFile(fileName);
                        if(this->_fileDescriptor == -1){
                                printf("Failed to open binary file.\n");
				error = true;
				return;
                        }

			this->ehdr.init(this->_fileData);
			this->phdr.init(this->_fileData);
			this->shdr.init(this->_fileData);
			

			if(this->ehdr.class32){
				this->class32 = true;
			}else{
				this->class32 = false;
			}
		
			this->shdr.setIndex(this->ehdr.shstrndx());
			this->_stringTable = (uint8_t *)&this->_fileData[shdr.offset()];
		}

		void manualFree(void){
			if(-1 != this->_fileDescriptor) close(this->_fileDescriptor);
		}

		/*
		 * Deconstructor functions
		 * */

		~ElfSnake(void){
			this->manualFree();
		}
		
		/*
		 * User Functions
		 * */
		int getSectionDataSize(int idx){
			return class32 ? ((Elf32_Shdr*)this->getSectionHeader(idx))->sh_size : ((Elf64_Shdr *)this->getSectionHeader(idx))->sh_size;
		}

		int getSectionDataOffset(int idx){
			return class32 ? ((Elf32_Shdr*)this->getSectionHeader(idx))->sh_offset : ((Elf64_Shdr *)this->getSectionHeader(idx))->sh_offset;
		}
		uint8_t *getSectionData(int idx){
			return (uint8_t *)&this->_fileData[this->getSectionDataOffset(idx)];
		}
		int getProgramHeaderCount(void){
			return (int)this->ehdr.phnum();
		}
	
		int getSectionHeaderCount(void){
			return (int)this->ehdr.shnum();
		}

		bool elfIs32(void){
			return class32;
		}

		void *getHeaderX(void){
			return this->ehdr.header();
		}
		
		void printHeader(void){
			printf("Header Info for '%s'\n", this->_fileName.c_str());
			printf("Type: %s\n", this->getFileType().c_str());
			printf("Machine: %s\n", this->getMachineType().c_str());
			printf("Version: %d\n", this->ehdr.version());
			printf("Entry: 0x%x\n", this->ehdr.entry());
			printf("Program Header Offset: %d\n", this->ehdr.phoff());
			printf("Section Header Offset: %d\n", this->ehdr.shoff());
			printf("Flags : %x\n", this->ehdr.flags());
			printf("Header Size: %d\n", this->ehdr.ehsize());
			printf("Program Header Size : %d\n", this->ehdr.phentsize());
			printf("Program Header Count : %d\n", this->ehdr.phnum());
			printf("Section Header Size: %d\n", this->ehdr.shentsize());
               		printf("Section Header Count : %d\n", this->ehdr.shnum());
			printf("Section Header String Table Index: %d\n", this->ehdr.shstrndx());
		}

		/*
		 * Must be type casted relative to elf archetecture. To
		 * Either Elf32_Phdr* or Elf64_Phdr* upon return of the result
		 */
		void *getProgramHeader(int idx){
			this->phdr.setIndex(idx);
			return this->phdr.header();
		}

		/*
		 * Must be type casted relative to elf archetecture. 
		 */
		void *getSectionHeader(int idx){
			void *ret = NULL;
			long int initalOffset = (long int)this->ehdr.shoff();
			long int cellSize = (long int)this->ehdr.shentsize();
			ret = (void *)&this->_fileData[initalOffset + (cellSize * idx)];
			return ret;
		}
	
		void printProgramHeader(int idx){
			this->phdr.setIndex(idx);
			printf("Segment Type: | Segment Offset | V Address | P Address | File Size | Memory Size | Flags | Alignment\n");
			printf("%s|\t%lx|\t0x%lx|\t0x%lx|\t0x%lx|\t0x%lx|\t0x%lx|\t0x%lx\n",
				getSegmentType((void *)this->phdr.header()).c_str(),
				(long)this->phdr.offset(),
				(long)this->phdr.vaddr(),
               			(long)this->phdr.paddr(),
               			(long)this->phdr.filesz(),
               			(long)this->phdr.memsz(),
               			(long)this->phdr.flags(),
               			(long)this->phdr.align()
			);
		}

		void printSectionHeader(int idx, bool printHeader){
			printf("\n");
			if(elfIs32()){
				if(printHeader)
				printf("Name | Type | Flags | Address | Offset | Size | Link | Info | Alignment | Entity Size\n");
				Elf32_Shdr *sheader = (Elf32_Shdr *)getSectionHeader(idx);
				printf("%s\t%s\t%s\t%lx\t%lx\t%lx\t%lx\t%lx\t%lx\t%lx\t",
					getSectionName(idx).c_str(),
               				getSectionType(idx).c_str(),
               				getSectionFlag(idx).c_str(),
               				(long)sheader->sh_addr,
               				(long)sheader->sh_offset,
               				(long)sheader->sh_size,
               				(long)sheader->sh_link,
               				(long)sheader->sh_info,
               				(long)sheader->sh_addralign,
               				(long)sheader->sh_entsize
				);
			}else{
				if(printHeader)
				printf("Name | Type | Flags | Address | Offset | Size | Link | Info | Alignment | Entity Size\n");
				Elf64_Shdr *sheader = (Elf64_Shdr *)getSectionHeader(idx);
				printf("%s\t%s\t%s\t%lx\t%lx\t%lx\t%lx\t%lx\t%lx\t%lx\t",
					getSectionName(idx).c_str(),
               				getSectionType(idx).c_str(),
               				getSectionFlag(idx).c_str(),
               				(long)sheader->sh_addr,
               				(long)sheader->sh_offset,
               				(long)sheader->sh_size,
               				(long)sheader->sh_link,
               				(long)sheader->sh_info,
               				(long)sheader->sh_addralign,
               				(long)sheader->sh_entsize
				);
			}
		}

		std::string getFileType(void){
        		std::string ret = "";
        		uint16_t type = this->ehdr.type();

        		switch(type){
        		        case ET_NONE:
        		        ret = "NONE";
        		        break;
        		        case ET_REL:
        		        ret = "REL";
        		        break;
        		        case ET_EXEC:
        		        ret = "EXEC";
        		        break;
        		        case ET_DYN:
        		        ret = "DYN";
        		        break;
        		        case ET_CORE:
        		        ret = "CORE";
        		        break;
        		}
        		return ret;
		}

		std::string getMachineType(void){
			switch(this->ehdr.machine()){
				case EM_NONE:
					return "An unknown machine";
              			case EM_M32:
					return "AT&T WE 32100";
              			case EM_SPARC:
					return "Sun Microsystems SPARC";
              			case EM_386:
					return "Intel 80386";
              			case EM_68K:
					return "Motorola 68000";
              			case EM_88K:
					return "Motorola 88000";
              			case EM_860:
					return "Intel 80860";
              			case EM_MIPS:
					return "MIPS RS3000 (big-endian only)";
              			case EM_PARISC:
					return "HP/PA";
              			case EM_SPARC32PLUS:
					return "SPARC with enhanced instruction set";
              			case EM_PPC:
					return "PowerPC";
              			case EM_PPC64:
					return "PowerPC 64-bit";
              			case EM_S390:
					return "IBM S/390";
              			case EM_ARM:
					return "Advanced RISC Machines";
              			case EM_SH:
					return "Renesas SuperH";
              			case EM_SPARCV9:
					return "SPARC v9 64-bit";
              			case EM_IA_64:
					return "Intel Itanium";
              			case EM_X86_64:
					return "AMD x86-64";
              			case EM_VAX:
					return "DEC Vax";
				default:
					return "An unknown machine";
			}
		}

		std::string getSectionFlag(int idx){
			long int ctx = class32 ? ((Elf32_Shdr *)this->getSectionHeader(idx))->sh_flags : ((Elf64_Shdr *)this->getSectionHeader(idx))->sh_flags;
			std::string ret = "";
			if((ctx&SHF_WRITE) == SHF_WRITE) ret += "W";
			if((ctx&SHF_ALLOC) == SHF_ALLOC) ret += "A";
			if((ctx&SHF_EXECINSTR) == SHF_EXECINSTR) ret += "E";
			if((ctx&SHF_MASKPROC) == SHF_MASKPROC) ret += "M";
			
			return ret;	
		}
		std::string getSectionType(int idx){
			long int ctx = class32 ? ((Elf32_Shdr *)this->getSectionHeader(idx))->sh_type : ((Elf64_Shdr *)this->getSectionHeader(idx))->sh_type;
			switch(ctx){
				case SHT_NULL:
					return "NULL";
              			case SHT_PROGBITS:
              				return "PROGBITS";
              			case SHT_SYMTAB:
              				return "SYMTAB";
              			case SHT_STRTAB:
              				return "STRTAB";
              			case SHT_RELA:
              				return "RELA";
              			case SHT_HASH:
              				return "HASH";
              			case SHT_DYNAMIC:
              				return "DYNAMIC";
              			case SHT_NOTE:
              				return "NOTE";
              			case SHT_NOBITS:
              				return "NOBITS";
              			case SHT_REL:
              				return "REL";
              			case SHT_SHLIB:
              				return "SHLIB";
              			case SHT_DYNSYM:
              				return "DYNSYM";
              			case SHT_LOPROC:
              				return "LOPROC";
				case SHT_HIPROC:
					return "HIPROC";
				case SHT_LOUSER:
					return "LOUSER";
              			case SHT_HIUSER:
              				return "HIUSER";
				default:
					return "UNKNOWN";
			}
		}

				
		
		std::string getSegmentType(void *phdr){
			int ctx = elfIs32() ? ((Elf32_Phdr *)phdr)->p_type : ((Elf64_Phdr *)phdr)->p_type;
			
			switch(ctx){
				case PT_NULL:
					return "NULL";
                 		case PT_LOAD:
                 			return "LOAD";
                 		case PT_DYNAMIC:
                 			return "DYNAMIC";
                 		case PT_INTERP:
                 			return "INTERP";
                 		case PT_NOTE:
                 			return "NOTE";
                 		case PT_SHLIB:
                 			return "SHLIB";
                 		case PT_PHDR:
                 			return "PHDR";
                 		case PT_LOPROC:
                 			return "LOPROC";
				case PT_HIPROC:
					return "HIPROC";
                 		case PT_GNU_STACK:
                 			return "GNU_STACK";
			}

			return "UNKNOWN TYPE";
		}

		std::string getSectionName(int idx){
			int nameIdx = elfIs32() ? (int)((Elf32_Shdr *)getSectionHeader(idx))->sh_name : (int)((Elf64_Shdr *)getSectionHeader(idx))->sh_name;
			const char * retc = (const char *)&this->_stringTable[nameIdx];
			std::string ret = retc;
			return ret;
		}


		Elf64_Ehdr *getHeader(void){
			return this->ehdr.header_64();
		}

		Elf32_Ehdr *getHeader32(void){
			return this->ehdr.header_32();
		}

		
		Elf64_Phdr *getProgramHeader(void){
			return (Elf64_Phdr *)&this->_fileData[this->ehdr.phoff()];
		}
		
		Elf32_Phdr *getProgramHeader32(void){
			return (Elf32_Phdr *)&this->_fileData[this->ehdr.phoff()];
		}
};
