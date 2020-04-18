#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <string.h>

#include <pcap.h>
#include "device.h"

#include <pthread.h>
#include <signal.h>
#include <future>

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

        void translate(const char *dev);

        //const u_char *next_packet_stoppable(pcap_t *handle_t, pcap_pkthdr header_t, bool *stop);

    
};

translator::~translator(){};


translator::translator(int argc, char const *argv[]){
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
        
    default:
        break;
    }
    current_net = devHandler.choosed;
}

static const u_char *next_packet_stoppable(device *dev, pcap_pkthdr header_t)
{
    std::mutex m;
    std::condition_variable cv;
    const u_char *retValue;

    std::thread t([&cv, &retValue, dev, &header_t]() 
    {
        retValue = pcap_next(dev->gethandle(), &header_t);
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(dev->block) 
            throw std::runtime_error("Timeout");
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

static void recvsend(device &toRecv, device &toSend){
    try
    {
        pcap_pkthdr cur_header;
        const u_char *packetAP = next_packet_stoppable(&toRecv, cur_header);
        
        toSend.block = true;         
        pcap_sendpacket(toSend.gethandle(), packetAP, cur_header.len);
        toSend.block = false;

        print_packet(cur_header, packetAP);

        recvsend(toRecv, toSend);
    }
    catch(const std::exception& e)
    {
        recvsend(toRecv, toSend);
    }
}

static const u_char *catch_packet(device *first, device *second){
    std::mutex m1;
    const u_char *retValue;
    retValue = NULL;


    
    std::thread t1([&retValue, &m1, &first]() 
    {
        const u_char *ans1 = pcap_next(first->gethandle(), &first->header);
        if(ans1 != NULL){            
            m1.lock();
            retValue = ans1;        
            first->block = true;
            m1.unlock();  
        }      
    }); 

    std::thread t2([&retValue, &m1, &second]() 
    {
        const u_char *ans2 = pcap_next(second->gethandle(), &second->header);
        if(ans2 != NULL){
            m1.lock();
            retValue = ans2;        
            second->block = true;
            m1.unlock();
        }        
    });    
    
    t1.detach();
    t2.detach();

    pcap_breakloop(first->gethandle());
    pcap_breakloop(second->gethandle());
    sleep(5);
    
    return retValue;
}

static void send_packet(const u_char *packet, device *first, device *second){
    if(first->block){
        pcap_sendpacket(second->gethandle(), packet, first->header.len); 
        print_packet(first->header, packet);       
    }
    if(second->block){
        pcap_sendpacket(first->gethandle(), packet, second->header.len);
        print_packet(second->header, packet); 
    }
    
    first->block = false;
    second->block = false;
}


void translator::translate(const char* devDST){                                            
   
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

    /*std::thread thrAP(recvsend, std::ref(devHandler), std::ref(dev2Handler));

    std::thread thrDST(recvsend, std::ref(dev2Handler), std::ref(devHandler));

    thrAP.detach();
    thrDST.detach();*/
    while(true){
        send_packet(catch_packet(&devHandler, &dev2Handler), &devHandler, &dev2Handler);
    }
    
}