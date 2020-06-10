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
        //device devHandler;
        //device dev2Handler;
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
        device devHandler;
        device dev2Handler;

        translator(int argc, char const *argv[]);
        
        ~translator();

        void halfduplex_translate(device *first, device *second);    
        void simplex_translate(device *first, device *second, bool printing);
        
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

void print_packet(struct pcap_pkthdr header, const u_char * packet){
    system("clear");
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
        packet++;
    }
    printf("\n======NEXT======\n");
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
            //sleep(5);
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
            //sleep(5);
        }        
    });    
    
    t1.detach();
    t2.detach();

    pcap_breakloop(first->gethandle());
    pcap_breakloop(second->gethandle());
    //sleep(1);
    
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

void translator::simplex_translate(device *first, device *second, bool printing){
    first->changeChannel(current_net.get_channel());
    second->changeChannel(current_net.get_channel());
    
    pcap_freecode(&first->fp);

    string filter_expression = "ether addr1 ";
    filter_expression.append(current_net.get_bssid());
    filter_expression.append(" || ether addr2 ");
    filter_expression.append(current_net.get_bssid());
    filter_expression.append(" || ether addr3 ");
    filter_expression.append(current_net.get_bssid());
    filter_expression.append(" || ether addr4 ");
    filter_expression.append(current_net.get_bssid());

    pcap_compile(first->gethandle(), &first->fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(first->gethandle(), &first->fp);

    const u_char *packet;

    while(true){
        packet = pcap_next(first->gethandle(), &first->header);
        if(printing)        print_packet(first->header, packet);
        pcap_sendpacket(second->gethandle(), packet, first->header.len);
    }
};

void translator::halfduplex_translate(device *first, device *second){
    first->changeChannel(current_net.get_channel());
    second->changeChannel(current_net.get_channel());

    pcap_freecode(&first->fp);
    //pcap_freecode(&second->fp);

    string filter_expression_AP = "ether src ";
    string filter_expression_DST = "ether dst ";
    filter_expression_AP.append(current_net.get_bssid());
    filter_expression_DST.append(current_net.get_bssid());

    pcap_compile(first->gethandle(), &first->fp, filter_expression_AP.c_str(), 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(first->gethandle(), &first->fp);

    pcap_compile(second->gethandle(), &second->fp, filter_expression_DST.c_str(), 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(second->gethandle(), &second->fp);

    while(true){
        send_packet(catch_packet(first, second), first, second);
    }
}