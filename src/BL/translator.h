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
        struct pcap_pkthdr header;
        const u_char *packet;
    
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


    
    //devHandler.shutdownDev();
    //devHandler.activateDev();

    devHandler.changeChannel(current_net.get_channel());  //command failed: Device or resource busy (-16)
    
    printf("%d",devHandler.getChannel());

    struct bpf_program fp;

    string filter_expression = "ether host ";
    filter_expression.append(current_net.get_bssid());

    printf("%s", filter_expression.c_str());
    //filter_expression = "type mgt subtype beacon";

    if (pcap_compile(devHandler.gethandle(), &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN)==-1){
        printf("%s",pcap_geterr(devHandler.gethandle()));
    }
    if (pcap_setfilter(devHandler.gethandle(), &fp)==-1){
        printf("%s",pcap_geterr(devHandler.gethandle()));
    }
    printw("\nTranslate? Press any key...\n");
    refresh();
    getch();
    translate();
}

void translator::translate(){
    int nextchannel = current_net.get_channel();
    while(1){
        clear();
        

        packet = pcap_next(devHandler.gethandle(), &header);    //подходит только header из translate
        printw("%d\n",header.len);
        refresh();
        for(int i = 0; i<header.len; i++){
            if(packet == NULL) continue;
            if(isprint(*packet)){
                printw("%c", *packet);
            }
            else
            {
                printw(".");
            }
            if(i%64==0){
                printw("\n");
            }
            refresh();
            packet++;
        }
        
    }
}