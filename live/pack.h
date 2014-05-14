#ifndef _LIVE_DEPACK_H_ 
#define _LIVE_DEPACK_H_ 

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "./a_depack.h"

#include "../pelib/PeLib.h"
#include "../pelib/PeLibAux.h"

#include "../aplib/aplib.h"

namespace live
{
        //unsigned int ratio(unsigned int x, unsigned int y);
        //int callback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam);

        template<int bits>
        class Pack
        {
        public:
            //Rajoute à la fin du vecteur un nouveau layer d'encryption
            int pack(std::vector< char> &vec,int section_number,int section_to_compress,PeLib::PeFileT<bits> &file);
        };

        template<int bits>
        int Pack<bits>::pack(std::vector< char> &vec,int section_number,int section_to_compress,PeLib::PeFileT<bits> &file)
        {

            int new_eip = file.peHeader().getVirtualAddress(section_number)+vec.size();
            unsigned int old_size = vec.size();
            
            //Compression de la section 1
            unsigned int max_section_size   = file.peHeader().getSizeOfRawData(section_to_compress);
            if(max_section_size ==0)
            {
                std::cout << "Skipping section " << section_to_compress << std::endl;
                return -1;
            }

            std::cout << "Compressing section " << section_to_compress << " [" << std::hex << max_section_size << "] ->";
            
            int max_packed = aP_max_packed_size(max_section_size);
            unsigned char * workmem         = (unsigned char*) malloc(aP_workmem_size(max_section_size));

            //Augmente la taille du vecteur pour contenir les données packées             
            vec.resize(vec.size()+sizeof(A_DEPACK_shellcode)+max_packed);

            file.peHeader().setSizeOfRawData(section_number,vec.size());

            memcpy(&vec[old_size],
                         A_DEPACK_shellcode,
                         sizeof(A_DEPACK_shellcode)
                         );
                         
             //sizeof(shellcode)-1 car sizeof("1") == 2, nous on veut la taille exacte! pas de 0 de fin de chaine

            unsigned int packed_size = /*aPsafe_pack*/aP_pack(reinterpret_cast<unsigned char *>(&file.peHeader().sectionsData()[section_to_compress][0]),
                                         reinterpret_cast<unsigned char *>(&vec[old_size+sizeof(A_DEPACK_shellcode)-1]),
                                         max_section_size, workmem, NULL, NULL);
            std::cout << " [" << std::hex << packed_size << "]" << std::endl;

            //Modify section size !
            vec.resize(old_size+packed_size+sizeof(A_DEPACK_shellcode) );
            file.peHeader().setSizeOfRawData(section_number,vec.size() );
            file.peHeader().setVirtualSize(section_number,vec.size());
            
            //
            // set parameters
            //
            *A_DEPACK_relative_EIP( (&vec[old_size]) )= file.peHeader().getAddressOfEntryPoint() - (new_eip+5);
            *A_DEPACK_relative_start_decrypt( (&vec[old_size]) ) = file.peHeader().getVirtualAddress(section_to_compress) - (new_eip+5) ;
            *A_DEPACK_size( (&vec[old_size]) ) = packed_size;

            // Modify EP
            file.peHeader().setAddressOfEntryPoint(new_eip);
            
            //Change size of section compressed -> 0
            file.peHeader().setSizeOfRawData(section_to_compress,0);
            
            //Allowing write on that section
            file.peHeader().setCharacteristics(section_to_compress,file.peHeader().getCharacteristics(section_to_compress) | PeLib::PELIB_IMAGE_SCN_MEM_WRITE);
            
            free(workmem);

            return new_eip;
        };
}
#endif /*_LIVE_CRYPT_RANGE_H_*/
