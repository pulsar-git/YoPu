#ifndef _LIVE_IAT_IMPORT_H_ 
#define _LIVE_IAT_IMPORT_H_ 

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "./a_iat.h"

#include "../PeLib/PeLibAux.h"
#include "../PeLib/ImportDirectory.h"




/*
* ATTENTION!!!
*
* Si jamais l'IAT se trouve dans une section qui n'est pas que à elle
* et que l'on compresse, ou crypte... la section auparavant,
* ca ne marchera pas, car on se base sur les données ici...
*
* todo modifier ca, et aussi virer la section qui contient l'IAT
* lorsqu'il n'y a que l'iat dans cette section et pas de code.
*/

namespace live
{
        template<int bits>
        class IatImport
        {
        public:
            //Rajoute à la fin du vecteur un nouveau layer d'encryption
            int iat_import(std::vector< char> &vec,int section_number,PeLib::PeFileT<bits> &file);
        };

        template<int bits>
        int IatImport<bits>::iat_import(std::vector< char> &vec,int section_number,PeLib::PeFileT<bits> &file)
        {
            if (file.readImportDirectory())
        	{
        		std::cout << "Import Directory not found...skipping IatImport" << std::endl;
        		return 0;
        	}
            std::cout << "Rebuilding IAT"  << std::endl;
            int new_eip = file.peHeader().getVirtualAddress(section_number)+vec.size();

            size_t old_size = vec.size();

            vec.resize(vec.size()+sizeof(A_IAT_shellcode));

            memcpy(&vec[old_size],
                         A_IAT_shellcode,
                         sizeof(A_IAT_shellcode)
                         );
            
            //
            // set parameters
            //
            *A_IAT_relative_goto( (&vec[old_size]) )= file.peHeader().getAddressOfEntryPoint() - (int) new_eip;
            //*A_CRYPT_RANGE_relative_start_decrypt( (&vec[old_size]) ) = rva_start_of_encryption - (new_eip+5) ;
            //*A_CRYPT_RANGE_size( (&vec[old_size]) ) = size;
            
            // Modify EP
            file.peHeader().setAddressOfEntryPoint(new_eip);
            
            //
            //  Fill Sections!
            //
            const PeLib::ImportDirectory<bits>& imp = static_cast<PeLib::PeFileT<bits>&>(file).impDir();
            std::vector < std::string > functions;
            std::vector < std::string > dll;

            // Get required informations (size of dll  & funtion array)
            for (unsigned int i=0;i<imp.getNumberOfFiles(PeLib::OLDDIR);i++)
        	{
                dll.push_back( imp.getFileName(i, PeLib::OLDDIR));

        		for (unsigned int j=0;j<imp.getNumberOfFunctions(i, PeLib::OLDDIR);j++)
                    functions.push_back( imp.getFunctionName(i, j, PeLib::OLDDIR) );
            }
            
            int desc_size = (int)( functions.size() )*(4*3)+4;
            int functions_array_size =0;
            int dll_array_size =0;
            for(int i=0;i<(int)dll.size();i++)
            {
                    dll_array_size += (dll[i].size()+1) < 6? 6:dll[i].size()+1;
            }
            for(int i=0;(int)i<(int)functions.size();i++)
            {
                    functions_array_size += (functions[i].size() == 0) ? 5 : functions[i].size()+1;
            }
            
            
            
            //
            // resize section to hold all that stuffs...
            //
            vec.resize(vec.size() + desc_size + dll_array_size + functions_array_size);
            int * iat_ptr  =  (int *)(old_size + sizeof(A_IAT_shellcode) -1);
            char * dll_ptr  = (char *)((int)(iat_ptr) + desc_size);
            char * old_dll_ptr  = 0;
            char * func_ptr = (char *)(dll_ptr + dll_array_size);
            
            iat_ptr = reinterpret_cast<int *>(&vec[(int)iat_ptr]);
            dll_ptr = reinterpret_cast<char *> (&vec[(int)dll_ptr]);
            func_ptr= reinterpret_cast<char *> (&vec[(int)func_ptr]);
                        
            for (unsigned int i=0;i<imp.getNumberOfFiles(PeLib::OLDDIR);i++)
        	{
                strcpy(dll_ptr,imp.getFileName(i, PeLib::OLDDIR).c_str());
                old_dll_ptr=dll_ptr;
                dll_ptr+=imp.getFileName(i, PeLib::OLDDIR).size()+1;
                std::cout << imp.getFileName(i, PeLib::OLDDIR) << "["<< imp.getNumberOfFunctions(i, PeLib::OLDDIR) << "]" << std::endl;

                int firstthunk = imp.getFirstThunk(i, PeLib::OLDDIR) - new_eip ;
                /*
        		dump(formatOutput("DLL Name", imp.getFileName(i, PeLib::OLDDIR)));
        		dump(formatOutput("OriginalFirstThunk", toString(imp.getOriginalFirstThunk(i, PeLib::OLDDIR)), "    "));
        		dump(formatOutput("TimeDateStamp", toString(imp.getTimeDateStamp(i, PeLib::OLDDIR)), "    "));
        		dump(formatOutput("ForwarderChain", toString(imp.getForwarderChain(i, PeLib::OLDDIR)), "    "));
        		dump(formatOutput("Name", toString(imp.getRvaOfName(i, PeLib::OLDDIR)), "    "));
        		dump(formatOutput("FirstThunk", toString(imp.getFirstThunk(i, PeLib::OLDDIR)), "    "));
        		dump("");
        		*/
        		
        		for (unsigned int j=0;j<imp.getNumberOfFunctions(i, PeLib::OLDDIR);j++)
        		{
                    *(iat_ptr++) = firstthunk; //Location
                    *(iat_ptr++) = (int)old_dll_ptr - (int)&vec[old_size] ; // DLL Name
                    *(iat_ptr++) = (int)func_ptr  - (int)&vec[old_size]; // Func Name

                    if(imp.getFunctionName(i, j, PeLib::OLDDIR).size() !=0 )
                    {
                          strcpy(func_ptr,imp.getFunctionName(i, j, PeLib::OLDDIR).c_str() );
                          func_ptr+=imp.getFunctionName(i, j, PeLib::OLDDIR).size()+1;
                    }
                    else
                    {
                          *((int *)func_ptr) = imp.getFunctionOrd(i,j,PeLib::OLDDIR);
                          func_ptr+=5;
                    }
                    firstthunk +=4;
                    /*
        			dump(formatOutput("Function Name", imp.getFunctionName(i, j, PeLib::OLDDIR), "    "));
        			dump(formatOutput("Hint", toString(imp.getFunctionHint(i, j, PeLib::OLDDIR)), "        "));
        			dump(formatOutput("First Thunk", toString(imp.getFirstThunk(i, j, PeLib::OLDDIR)), "        "));
        			dump(formatOutput("Original First Thunk", toString(imp.getOriginalFirstThunk(i, j, PeLib::OLDDIR)), "        "));
        			dump("");
        			*/
        		}
            }
           
            
            // Set characteristics of IAT to writeable
            int rva_section=file.peHeader().getSectionWithRva(file.peHeader().getIddImportRva());
            file.peHeader().setCharacteristics(rva_section,file.peHeader().getCharacteristics(rva_section) | PeLib::PELIB_IMAGE_SCN_MEM_WRITE);
            //file.peHeader().setSizeOfRawData(rva_section,0);
            

            //
            // Ajouter les fonctions dans l'imp Dir
            //

            file.impDir().clear();
            file.impDir().addFunction("Kernel32.dll", "LoadLibraryA");
            file.impDir().addFunction("Kernel32.dll", "GetProcAddress");           

            //
            // uImpDir = rva of impdir
            //
            int uiImpDir = file.peHeader().getVirtualAddress(section_number) + (int)func_ptr -  (int)&vec[old_size] + old_size ;
            // Set IddImportRva
            file.peHeader().setIddImportRva(uiImpDir);
            std::vector< PeLib::byte > buffer;
            file.impDir().rebuild(buffer, (PeLib::dword) uiImpDir);
            
            //
            // Modifier les pointeurs vers les fonctions!
            //

            *A_IAT_loadLibrary( (&vec[old_size]) ) = file.impDir().getFirstThunk("Kernel32.dll",PeLib::NEWDIR) - new_eip;
            *A_IAT_getprocadress( (&vec[old_size]) ) = file.impDir().getFirstThunk("Kernel32.dll",PeLib::NEWDIR) - new_eip +4;
            
            //Redimensionner le buffer de section
            vec.resize( vec.size() + buffer.size() );
            
            //Mettre à jours les tailles dans le PE
            file.peHeader().setSizeOfRawData(section_number,vec.size());
            file.peHeader().setVirtualSize(section_number,vec.size());
            
            //Modifier l'import size
            file.peHeader().setIddImportSize(file.impDir().size());

            return new_eip;
        };
}
#endif /*_LIVE_IAT_IMPORT_H_*/
