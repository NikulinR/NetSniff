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
        device dev2Handler;
        network current_net;
        void recvsendAP();
        void recvsendDST();
        bool stopAP = false;
        bool stopDST = false;

        struct pcap_pkthdr headerDST;
        struct pcap_pkthdr headerAP;

        pcap_t *handleDST;

        const u_char *packetDST;
        const u_char *packetAP;
    
    public:
        translator(int argc, char const *argv[]);
        
        ~translator();

        void compare_SSID_BSSID();
        void translate(const char *dev);
    
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
}

const u_char *next_packet_stoppable(pcap_t *handle_t, pcap_pkthdr *header_t, bool *stop)
{
    std::mutex m;
    std::condition_variable cv;
    const u_char *retValue;

    std::thread t([&cv, &retValue, &handle_t, header_t]() 
    {
        retValue = pcap_next(handle_t, header_t);
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(stop) 
            throw std::runtime_error("Timeout");
            //return NULL;
    }
    
    return retValue;    
}


void print_packet(struct pcap_pkthdr header, const u_char * packet){
    for(int i = 0; i<header.len; i++){
        if(packet == NULL) continue;
        if(isprint(*packet)){
            printf("%c", *packet);
        }
        else
        {
            printf("%02x ", *packet);
        }
        if(i%64==0){
            printf("\r\n");
        }
        //refresh();
        packet++;
    }
    printf("\n======NEXT======\n");
}

void translator::recvsendAP(){
    try
    {
        packetAP = next_packet_stoppable(devHandler.gethandle(),  &headerAP, &stopAP); 
        stopDST = true;         
        pcap_sendpacket(dev2Handler.gethandle(), packetAP, headerAP.len);
        stopDST = false;

        print_packet(headerAP, packetAP);

        recvsendAP();
    }
    catch(const std::exception& e)
    {
        recvsendAP();
    }
    
      
    
}

void translator::recvsendDST(){
    try
    {
        packetDST = next_packet_stoppable(dev2Handler.gethandle(),  &headerDST, &stopDST);   
        stopAP = true;         
        pcap_sendpacket(devHandler.gethandle(), packetDST, headerDST.len);
        stopAP = false;

        print_packet(headerDST, packetDST);

        recvsendDST();
    }
    catch(const std::exception& e)
    {
        recvsendDST();
    }
}



void translator::translate(const char* devDST){                                                       //ПОКАЗЫВАЕТ ТОЛЬКО HEADER БЕЗ PAYLOAD
   
    if(strcmp(devDST, devHandler.getDevice().c_str())){
        dev2Handler.name = devDST;
        dev2Handler.activateDev();
        handleDST = dev2Handler.gethandle();
        dev2Handler.changeChannel(current_net.get_channel());
    }
    else{
        handleDST = devHandler.gethandle();
        devHandler.changeChannel(current_net.get_channel());
    }

    struct bpf_program fpDST, fpAP;

    string filter_expression_AP = "ether src ";
    filter_expression_AP.append(current_net.get_bssid());

    string filter_expression_DST = "ether dst ";
    filter_expression_DST.append(current_net.get_bssid());
    
    pcap_freecode(&devHandler.fp);
    bool tryagain = false;
    do{
        tryagain = false;
        if (pcap_compile(devHandler.gethandle(), &fpAP, filter_expression_AP.c_str(), 0, PCAP_NETMASK_UNKNOWN)==-1){
            printf("%s",pcap_geterr(devHandler.gethandle()));
            tryagain = true;
        }
        if (pcap_setfilter(devHandler.gethandle(), &fpAP)==-1){
            printf("%s",pcap_geterr(devHandler.gethandle()));
            tryagain = true;
        }
    }
    while(tryagain);

    pcap_freecode(&dev2Handler.fp);
    do{
        tryagain = false;
        if (pcap_compile(dev2Handler.gethandle(), &fpDST, filter_expression_DST.c_str(), 0, PCAP_NETMASK_UNKNOWN)==-1){
            printf("%s",pcap_geterr(dev2Handler.gethandle()));
            tryagain = true;
        }
        if (pcap_setfilter(dev2Handler.gethandle(), &fpDST)==-1){
            printf("%s",pcap_geterr(dev2Handler.gethandle()));
            tryagain = true;
        }
    }
    while(tryagain);



    std::thread thrAP(&translator::recvsendAP, this);

    std::thread thrDST(&translator::recvsendDST, this);

    thrAP.detach();
    thrDST.detach();
}