#include "./BL/device.h"

#include <string>

#include <pthread.h>

int main(int argc, char const *argv[])
{ 
    setlocale(LC_ALL,"Russian");
    
    //TODO
    /*
    проверить ловятся ли beaconы
    при получении ssid 
        фиксировать канал 
        менять фильтр
        проверять mac-SSID
    */
    device DevHandler = device();
    if(argc==2){
        //при запуске передан интерфейс
        DevHandler.setDevice(std::string(argv[1]));
        DevHandler.searchAP();
    }
    else if(argc==3){
        //при запуске передан интерфейс и ssid
        DevHandler.setDevice(std::string(argv[1]));
        DevHandler.getAP(std::string(argv[2]));
    }
    else{
        DevHandler.searchDevs();
        DevHandler.searchAP();
    }
    //начать трансляцию
    
    return 0;
} 