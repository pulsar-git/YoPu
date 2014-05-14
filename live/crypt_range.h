#ifndef _LIVE_CRYPT_RANGE_H_ 
#define _LIVE_CRYPT_RANGE_H_ 

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "../pelib/PeLib.h"
#include "../pelib/PeLibAux.h"

#include "./a_crypt_range.h"

namespace live
{
        template<int bits>
        class CryptRange
        {
        public:
            //Rajoute à la fin du vecteur un nouveau layer d'encryption
            int crypt(std::vector< char> &vec,int section_number,int rva_start_of_encryption,int size,PeLib::PeFileT<bits> &file);
        };

        template<int bits>
        int CryptRange<bits>::crypt(std::vector< char> &vec,int section_number,int rva_start_of_encryption,int size,PeLib::PeFileT<bits> &file)
        {
            int new_eip = file.peHeader().getVirtualAddress(section_number)+vec.size();

            unsigned int old_size = vec.size();

            vec.resize(vec.size()+sizeof(A_CRYPT_RANGE_shellcode));
            file.peHeader().setSizeOfRawData(section_number,vec.size());
            file.peHeader().setVirtualSize(section_number,vec.size());

            memcpy(&vec[old_size],
                         A_CRYPT_RANGE_shellcode,
                         sizeof(A_CRYPT_RANGE_shellcode)
                         );
            
            //
            // set parameters
            //
            *A_CRYPT_RANGE_relative_goto( (&vec[old_size]) )= file.peHeader().getAddressOfEntryPoint() - (new_eip+5);
            *A_CRYPT_RANGE_relative_start_decrypt( (&vec[old_size]) ) = rva_start_of_encryption - (new_eip+5) ;
            *A_CRYPT_RANGE_size( (&vec[old_size]) ) = size;

            char key = (rand() % 0xFF)+1;
            *A_CRYPT_RANGE_key ( (&vec[old_size]) )= (int)(key)&(~0xFFFFFF00);
            
            // Modify EP
            file.peHeader().setAddressOfEntryPoint(new_eip);

            //
            // Attention ici, si jamais on crypte a cheval sur plusieurs sections, ca plantera...
            //

            //Get section containing data
            int secNumber = file.peHeader().getSectionWithRva(rva_start_of_encryption);

            // Attention, si jamais on est dans  la nouvelle section, on ne peut pas la trouver par sectionsData (pas encore ajoutée)
            std::vector <char> *dVec = &vec;
            if(secNumber !=section_number)
                         dVec=&(file.peHeader().sectionsData()[secNumber]);
            
            int start_index = rva_start_of_encryption - file.peHeader().getVirtualAddress(secNumber);
            for(int i=start_index;i<start_index+size;i++)
                    (*dVec)[i] = (*dVec)[i] ^ ((int)(key)&(~0xFFFFFF00));

            return new_eip;
        };
}
#endif /*_LIVE_CRYPT_RANGE_H_*/
