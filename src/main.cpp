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
    printf("You choosed %s",DevHandler.getDevice().c_str());



    return 0;
} 