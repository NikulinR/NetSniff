#include "./BL/device.h"

#include <string>

#include <pthread.h>

int main(int argc, char const *argv[])
{ 
    setlocale(LC_ALL,"Russian");
    
    /*===================================================
    ===================CHOOSING DEVICE===================
    ===================================================*/
    device DevHandler = device();
    DevHandler.searchAP();

    
    return 0;
} 