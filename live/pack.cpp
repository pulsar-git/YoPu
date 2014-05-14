#include <iostream>
#include "pack.h"

namespace live
{
    /*
     * Compute ratio between two numbers.
     */
    unsigned int ratio(unsigned int x, unsigned int y)
    {
        if (x <= UINT_MAX / 100) x *= 100; else y /= 100;
    
        if (y == 0) y = 1;
    
        return x / y;
    }
    
    /*
     * Compression callback.
     */
    int callback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam)
    {
       printf("\rcompressed %u -> %u bytes (%u%% done)", inpos, outpos, ratio(inpos, insize));
    
       return 1;
    }
};
