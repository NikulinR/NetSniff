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
    

    devHandler.changeChannel(current_net.get_channel());  //command failed: Device or resource busy (-16)
    
    printf("%d\r\n",devHandler.getChannel());

    struct bpf_program fp;

    string filter_expression = "ether host ";
    filter_expression.append(current_net.get_bssid());

    printf("%s\r\n", filter_expression.c_str());
    //filter_expression = "type mgt subtype beacon";
    
    pcap_freecode(&devHandler.fp);
    bool tryagain = false;
    do{
        tryagain = false;
        if (pcap_compile(devHandler.gethandle(), &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN)==-1){
            printf("%s",pcap_geterr(devHandler.gethandle()));
            tryagain = true;
        }
        if (pcap_setfilter(devHandler.gethandle(), &fp)==-1){
            printf("%s",pcap_geterr(devHandler.gethandle()));
            tryagain = true;
        }
    }
    while(tryagain);
    
    //translate(devHandler.getDevice().c_str());
    translate("enp4s0f1");
}

const u_char *next_packet_timed(pcap_t *handle_t, pcap_pkthdr *header_t, const std::chrono::microseconds timing)
{
    std::mutex m;
    std::condition_variable cv;
    const u_char *retValue;

    std::thread t([&cv, &retValue, &handle_t, &header_t]() 
    {
        retValue = pcap_next(handle_t, header_t);
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(cv.wait_for(l, timing) == std::cv_status::timeout) //how to kill thread???
            throw std::runtime_error("Timeout");
            //return 0;
    }

    return retValue;    
}

void translator::translate(const char* dev){                                                       //ПОКАЗЫВАЕТ ТОЛЬКО HEADER БЕЗ PAYLOAD
    int nextchannel = current_net.get_channel();
    bool isFixed = false;

    
    pcap_t *handle;

    char *errbuf;

    if(strcmp(dev, devHandler.getDevice().c_str())){
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    }
    else {
        handle = devHandler.gethandle();
    }
    //std::chrono::microseconds timing = 400ms;
    while(1){
        try
        {
            //packet = next_packet_timed(devHandler.gethandle(), &header, timing);    //подходит только header из translate
            packet = pcap_next(devHandler.gethandle(),  &header);
            pcap_sendpacket(handle, packet, header.len);
        }
        catch (const std::exception&)
        {
            //timing = 4000ms;
            /*nextchannel = nextchannel % 12 + 5;
            devHandler.changeChannel(nextchannel);
            printf("\r\nTIMEOUT");*/
            continue;
        }
        
        //timing = 2000ms;
        
        printf("%d\r\n",header.len);

        //refresh();
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
}