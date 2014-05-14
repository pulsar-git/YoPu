#include <cstdlib>
#include <iostream>
#include <fstream>
#include <cctype>
#include <string>
#include <iterator>
#include <locale>
#include <algorithm>

using namespace std;
struct ToUpper
{
       ToUpper(std::locale const& l) : loc(l) {;}
       char operator() (char c) const { return std::toupper(c,loc);}
private:
        std::locale const& loc;
};

struct ToLower
{
       ToLower(std::locale const& l) : loc(l) {;}
       char operator() (char c) const { return std::tolower(c,loc);}
private:
        std::locale const& loc;
};

int extract_struct(std::ifstream &source,std::ofstream &dest,std::string &prefix);

char * extract_info(char *buffer,std::ofstream &dest,std::string &prefix);

#define MAX_SHELLCODE_SIZE 20

int main(int argc, char *argv[])
{
    if (argc <= 1)
	{
		std::cout << "Usage: liveit <filename>" << std::endl;
		return 1;
	}
 
    std::string name(argv[1]);
    std::ifstream ifFile((name+".asm").c_str());
    std::ofstream ofFile((name+".h").c_str());

    ToUpper up(std::locale::classic());
	
    if (!ifFile || !ofFile)
    {
        std::cout << "file <" << name << ".asm> does not exist!"  << std::endl;
    	return 1;
    }
    ifFile.close();
    std::string prefix=name;
    std::transform(name.begin(),name.end(),prefix.begin(),up);
    
    // Print prefix #ifndef _LIVE_LOADER_H_
    //              #define _LIVE_LOADER_H_
    
    ofFile << "#ifndef _LIVE_" << prefix << "_H_ " << std::endl;
    ofFile << "#define _LIVE_" << prefix << "_H_ " << std::endl << std::endl;
    
    ofFile << "#include \"live_macro.h\"" << std::endl << std::endl;
     
    
    system(("nasmw.exe -O3 "+name+".asm").c_str());
    
    
    std::ifstream binary(name.c_str(),std::ios::binary);
    binary.seekg(0, std::ios::end);
	int shellsize = binary.tellg();
	binary.seekg(0, std::ios::beg);
    char *buffer = (char *) malloc(shellsize+1);
    binary.read(buffer,shellsize);
    binary.close();
    buffer[shellsize]=0xFF;
 
    int max_shellcode = shellsize-sizeof("LIVE_START");
    for(;max_shellcode>0;max_shellcode--)
      if(buffer[max_shellcode]=='L' &&
         buffer[max_shellcode+1]=='I' &&
         buffer[max_shellcode+2]=='V' &&
         buffer[max_shellcode+3]=='E' &&
         buffer[max_shellcode+4]=='_' &&
         buffer[max_shellcode+5]=='S' &&
         buffer[max_shellcode+6]=='T' &&
         buffer[max_shellcode+7]=='A' &&
         buffer[max_shellcode+8]=='R' &&
         buffer[max_shellcode+9]=='T'
         )
         break;
//    std::cout << "found LIVE_START beggining at " << std::hex << max_shellcode << std::endl;

    //
    // Extracting shellcode
    //
    ofFile << "static char " << prefix << "_shellcode[]= "<<std::endl;
    ofFile << "\""; // start of line
    int counter=0;
    for(int i=0;i<max_shellcode;i++)
    {
        ofFile << "\\x" << std::hex << (int)((int)buffer[i]&(~0xFFFFFF00));
        counter++;
        if(counter>=MAX_SHELLCODE_SIZE)
        {
         ofFile << "\"\\"<< std::endl<<"\"";
         counter=0;
        }    
    }
    ofFile << "\";" << std::endl << std::endl;
    
    //
    // Extracting infos
    //
    char * ptr=&buffer[max_shellcode]+sizeof("LIVE_START");
    while( (ptr=extract_info(ptr,ofFile,prefix)) !=0 )
    {
    }
    ofFile <<  std::endl;
    ofFile << "#endif /*_LIVE_" << prefix << "_H_*/ " << std::endl;
    
    ofFile.close();
    return 0;
}

char * extract_info(char *buffer,std::ofstream &dest,std::string &prefix)
{
    if(buffer[0] != ' ')
    {
      return 0;
    }
 
    std::string name (buffer+1); //Sauter l'espace!
    int * taille = (int *)(buffer+strlen(buffer)+1);
    int * position = (int *)(buffer+strlen(buffer)+1+4);
    
    dest << "#define "  << prefix << "_" << name << "(x) \t" ;
    switch (*taille)
    {
         case 1:
              dest << "LIVE_PARAMETER(char,x,0x" << std::hex << *position <<") "; 
              break;
         case 4:
              dest << "LIVE_PARAMETER(int,x,0x" << std::hex << *position <<") "; 
              break;           
         
         default:
           dest << " \t0x" << std::hex << *position ;
    };
    dest << std::endl;
     
    return buffer+strlen(buffer)+1+8;    //se positionner sur le dword   
}


int extract_struct(std::ifstream &source,std::ofstream &dest,std::string &prefix)
{
    std::string word;
    std::string name,nameu,type,size;
    ToUpper up(std::locale::classic());
    
    source >> word; //get name of structure
    std::transform(word.begin(),word.end(),word.begin(),up);
    
    dest << "struct " << prefix << "_" << word << std::endl;
    dest << "{" << std::endl;
    
    while(1)
    {
        source >> name;
        nameu=name;
        std::transform(name.begin(),name.end(),nameu.begin(),up);
        
        if(nameu.find("ENDSTRUC") != std::string::npos )
         break;
        source >> type;
        source >> size;
        
        name.erase(0,1);
        dest << "\tint " << name << ";" <<  std::endl;
                
    }
    dest << "};" << std::endl << std::endl;
}
