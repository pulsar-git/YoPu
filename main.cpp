#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include <cstdio>

#include "./pelib/PeLib.h"
#include "./pelib/PeLibAux.h"

#include "./live/crypt_range.h"
#include "./live/pack.h"
#include "./live/iat_import.h"

#include "windows.h" //not portable innit :p

using namespace std;

void pack_pe(char * name);

template<typename T>
std::string toString(T x, char f = '0')
{
	std::stringstream ss;
	ss << std::setw(sizeof(T)*2) << std::setfill(f) << std::hex << std::uppercase << x;
	return ss.str();
}

template<>
std::string toString<PeLib::byte>(PeLib::byte x, char f)
{
	std::stringstream ss;
	ss << std::setw(2) << std::setfill(f) << std::hex << std::uppercase << (int)x;
	return ss.str();
}

std::string formatOutput(const std::string& text, const std::string& val, const std::string& pad = "", unsigned int maxsize = 70)
{
	std::stringstream ss;
	
	ss << pad << text << std::setw(maxsize - text.length() - val.length() - pad.length()) << std::setfill(' ') << "";
	ss << val;
	return ss.str();
}

std::string centerOutput(const std::string& text, unsigned int maxsize = 70)
{
	std::stringstream ss;
	
	unsigned int left = (maxsize - text.length()) / 2;
	ss << std::setw(left) << std::setfill(' ') << "";
	ss << text;
	
	return ss.str();
}

void dump(const std::string& d)
{
	std::cout << d << std::endl;
}

class PeRebuilderVisitor : public PeLib::PeFileVisitor
{
public:
    virtual void callback(PeLib::PeFile32 &file) {
                 std::string newFileName = file.getFileName();
                 newFileName.replace(newFileName.size()-4,4,"_new.exe");
                 // Delete old file...
                 remove(newFileName.c_str());
            	 file.peHeader().readSectionsData(file.getFileName());
                 dump("Adding section yopu");

                 //add section
                 int ret;
                 if((ret=file.peHeader().addSection("yopu", 0x100))!=NO_ERROR)
                 {
                   int numberofnewdir=0;
                   int mtintsize = file.peHeader().size() - file.peHeader().getNumberOfSections() * PeLib::PELIB_IMAGE_SECTION_HEADER::size();
                   
                   switch(ret)
                   {
                     case PeLib::ERROR_NOT_ENOUGH_SPACE:
                          
                          std::cout << "Pe Header ["<< mtintsize <<"] too small to add another section!" << std::endl;
                          
                          std::cout << "Trying to remove bindimportdirectory! (most win stuff...)" << std::endl;
                          
                          while(ret == PeLib::ERROR_NOT_ENOUGH_SPACE && numberofnewdir < 10)
                          {
                                 //file.peHeader().addDataDirectory();
                                 //file.peHeader().setPointerToRawData(0,file.peHeader().getPointerToRawData(0)+0x100);
                                 //file.peHeader().makeValid(file.mzHeader().getAddressOfPeHeader());
                                 file.peHeader().setIddBoundImportRva(0);
                                 ret=file.peHeader().addSection("yopu", 0x100);
                                 numberofnewdir++;
                          }

                          if(ret != NO_ERROR)
                          {
                                 std::cout << "Bah didn't worked..." << std::endl;
                                 return;
                          }
                                 
                          break;
                     
                     default:
                          std::cout << "Couille dans le potage pour addsection -> "<< ret << std::endl;
                          return;              
                   }
                 }
                 // Recalculate stuffs...                 
                 file.peHeader().makeValid(file.mzHeader().getAddressOfPeHeader());
                 
                 unsigned geo_section_number =file.peHeader().getNumberOfSections()-1;

                 // fill section with asm
                 std::vector<char> geo_section(0);

                 

                 //
                 // Grab IAT
                 //
                 live::IatImport<32> lImport;
                 lImport.iat_import(
                        geo_section,
                        geo_section_number,
                        file);
                 
                 //
                 // Pack first section
                 //
                 live::Pack<32> cpack;
                 
                 int new_eip=cpack.pack(
                        geo_section,
                        geo_section_number,
                        0, // section to compress!
                        file);
                 //
                 // Pack section 2
                 //                   
                 cpack.pack(
                        geo_section,
                        geo_section_number,
                        1, // section to compress!
                        file);

                 /*live::CryptRange<32> crange;
                 crange.crypt(
                        geo_section, //vector
                        geo_section_number, //section N°
                        new_eip, //va_start
                        geo_section.size() -(new_eip - file.peHeader().getVirtualAddress(geo_section_number) ) , //size
                        file //PeFile 
                        );*/

                 // Add section data...Change to addSectionData maybe!
                 file.peHeader().sectionsData().push_back(geo_section);
                 file.peHeader().makeValid(file.mzHeader().getAddressOfPeHeader());
                 dump("Writing to disk...");
                 file.write(newFileName.c_str());
            }
    virtual void callback(PeLib::PeFile64 &file) {
            }
};

int main(int argc, char *argv[])
{
    if (argc <= 1)
	{
		std::cout << "Usage: filedump <directory>" << std::endl;
		return 1;
	}
	
	
	//
	// A recoder pour devenir portable...
	//
	
	HANDLE hFind;
	WIN32_FIND_DATA FindData;
	
	SetCurrentDirectory(argv[1]);
	hFind=FindFirstFile("*.exe",&FindData);
	do
	{
        if(!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ))
    	{
          //Quand on trouve un fichier...
          if(strstr(FindData.cFileName,"_new.exe")==0)
            pack_pe(FindData.cFileName);
        }        
    } while(FindNextFile(hFind,&FindData));

	//pack_pe(argv[1]);

	return 0;
}

void pack_pe(char * name)
{
    std::string filename = name;
    PeLib::PeFile* pef = PeLib::openPeFile(filename);
	
	if (!pef)
	{
		std::cout << "Invalid PE File" << std::endl;
		return ;
	}

	pef->readMzHeader();
	pef->readPeHeader();


	dump(centerOutput("----------------------------------------------"));
	dump(centerOutput("PE Loaded"));
	dump(centerOutput("----------------------------------------------"));
	
	PeRebuilderVisitor  v2;
	pef->visit(v2);
	
	delete pef;     
}


