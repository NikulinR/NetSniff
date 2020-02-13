#include "./BL/translator.h"

#include <string>

#include <pthread.h>

int main(int argc, char const *argv[])
{ 
    setlocale(LC_ALL,"Russian");
    
    //TODO
    /*
    проверить ловятся ли beaconы
    при получении ssid 
        проверять mac-SSID
    */ 
    
    //выбор интерфейса и целевого ssid
    translator trans = translator(argc, argv);
    //начать трансляцию
    
    return 0;
} 