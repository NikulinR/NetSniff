#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <string.h>

#include <pcap.h>
#include "device.h"

using namespace std;

class translator{
    private:
        device devHandler;
        network current_net;
    
    public:
        translator(int argc, char const *argv[]);
        
        ~translator();

        void compare_SSID_BSSID();
        void translate();
    
};

translator::~translator(){};

translator::translator(int argc, char const *argv[]){
    devHandler = device();
    switch (argc)
    {
    case 1:
        devHandler.searchDevs();
        devHandler.searchAP();
        break;
    
    case 2:
        devHandler.setDevice(std::string(argv[1]));
        devHandler.searchAP();
        break;

    case 3:
        devHandler.setDevice(std::string(argv[1]));
        devHandler.getAP(std::string(argv[2]));  
        break;

    default:
        break;
    }
    current_net = devHandler.choosed;

    const u_char* packet = devHandler.next_packet();

    devHandler.changeChannel(current_net.get_channel());  //command failed: Device or resource busy (-16)
    
    struct bpf_program fp;

    if (pcap_compile(devHandler.gethandle(), &fp, "", 0, PCAP_NETMASK_UNKNOWN)==-1){
        printf("%s",pcap_geterr(devHandler.gethandle()));
    }
    if (pcap_setfilter(devHandler.gethandle(), &fp)==-1){
        printf("%s",pcap_geterr(devHandler.gethandle()));
    }
}
