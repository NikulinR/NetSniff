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

    trans.simplex_translate(&trans.devHandler, &second, true);
    
    //trans.halfduplex_translate(&trans.devHandler, &second);

    return 0;
} 