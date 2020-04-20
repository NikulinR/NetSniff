#include "./BL/translator.h"

#include <string>
#include <csignal>

#include <pthread.h>


int main(int argc, char const *argv[])
{ 
    setlocale(LC_ALL,"Russian");
    
    translator trans = translator(argc, argv);
    
    device second = device();
    second.searchDevs(); 

    trans.translate(second.getDevice().c_str());
    
    return 0;
} 