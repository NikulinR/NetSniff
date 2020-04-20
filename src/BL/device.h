#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <ncurses.h>

#include "radiotap.h"
#include "network.h"
#include "menu.h"

#define IDLE_TIME 1000ms
#define REP_COUNT 3

using namespace std;
using namespace std::chrono_literals;

class device
{
private:    
    int channel;
    pcap_if_t *pcap_dev;
    pcap_t *handle;
    string name;
    
    vector<string> available;
    vector<network> APs; 
    string current_ssid;
    vector<string> APs_SSIDs;
   
    int devCount;
    char *errbuf = new char[PCAP_ERRBUF_SIZE];
    
    int getDevCount(pcap_if_t devs);
    void getDevListNames(pcap_if_t *devs);    

public:
    device();
    device(string name);
    device(const char *name);
    ~device();

    struct pcap_pkthdr header;
    network choosed;
    
    struct bpf_program fp;
    int getChannel(){return channel;}
    vector<string> getDevs() {return available;}
    int getDevCount(){return devCount;}
    string getDevice(){return name;}
    pcap_t *gethandle(){return handle;}
    pcap_pkthdr *getHeader(){return &header;};
    void setDevice(string dev){name = dev;}
    void setDevice(const char *dev){name = dev;}
    bool block = false;

    void searchDevs();
    void activateDev();
    void shutdownDev();
    void searchAP();
    string *getAPs();
    void changeChannel(int ch);

    const u_char* next_packet(){return pcap_next(handle, &header);}
    const u_char* next_packet_timed(device *dev);
};

void device::searchDevs()
{
    pcap_findalldevs(&pcap_dev, errbuf);
    devCount = getDevCount(*pcap_dev);
    getDevListNames(pcap_dev);
    
    menu dev_menu = menu(available, "Please choose target device:");
    name = dev_menu.listen();
}

device::device(){
}

device::device(string name){
    this->name = name;
    this->activateDev();
}

device::device(const char *name){
    this->name = name;
    this->activateDev();
}


device::~device()
{
    
}


const u_char *device::next_packet_timed(device *dev)
{
    std::mutex m;
    std::condition_variable cv;
    const u_char *retValue;

    std::thread t([&cv, &retValue, dev]() 
    {
        retValue = dev->next_packet();
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(cv.wait_for(l, IDLE_TIME) == std::cv_status::timeout) 
            throw std::runtime_error("Timeout");
    }
    
    return retValue;    
}



int device::getDevCount(pcap_if_t devs){
    int res = 0;
    pcap_if_t *current = &devs;
    while(current != NULL)
    {
        current = current->next;
        res++;
    }
    return res;
}

void device::getDevListNames(pcap_if_t *devs)
{
    int size = getDevCount(*devs);
    pcap_if_t *current = devs;
    for (size_t i = 0; i < size; i++)
    {
        available.insert(available.end(), string(current->name));
        current = current->next;
    }
}

void device::shutdownDev(){
    printf("closed");
    pcap_close(handle);
}

void device::activateDev(){
    char bufdown[200];
    int isDone = snprintf(bufdown, 
                    sizeof(bufdown), 
                    "sudo ip link set %s down & sudo iw dev %s set monitor control & sudo ip link set %s up",
                    name.c_str(),name.c_str(),name.c_str()); 
    printf("%s\n",bufdown);
    
    while(system(bufdown)){
        continue;
    }

    handle = pcap_create(name.c_str(), errbuf);
    pcap_set_rfmon(handle, 1);
	//pcap_set_promisc(handle, 1); /* Capture packets that are not yours */
	pcap_set_snaplen(handle, 2048); /* Snapshot length */
	pcap_set_timeout(handle, 1000); /* Timeout in milliseconds */
	pcap_activate(handle);
    channel = 1;
    changeChannel(0);
}

void device::changeChannel(int ch){
        ch = ch % 12;
        if(ch == 0) ch = 1;

        char bufdown[60];
        char bufup[60];
        int isDone = snprintf(bufdown, 
                        sizeof(bufdown), 
                        "sudo iw dev %s set channel %d",
                        name.c_str(), ch); 
        //printf("%s\n\r",bufdown);
        while (system(bufdown)){
            continue;
        }

        channel = ch;    
}


void device::searchAP(){
    activateDev();
    
    if (pcap_compile(handle, &fp, "subtype beacon", 0, PCAP_NETMASK_UNKNOWN)==-1){
        printf("%s",pcap_geterr(handle));
        searchAP();
    }
    else if (pcap_setfilter(handle, &fp)==-1){
        printf("%s",pcap_geterr(handle));
        searchAP();
    }
    else{
        bool choosen = false;
        bool first_time = true;
        int nextchannel = channel;

        menu choosingAP = menu(APs_SSIDs,"Choose AP:");
        int counter = 0;

        const u_char *packet;

        initscr();
        timeout(30);
        keypad(stdscr, true); 

        while(!choosen){
            if(counter>REP_COUNT){
                counter = 0;            
                nextchannel = nextchannel % 12 + 5;
                changeChannel(nextchannel);
            }
            choosingAP.render_menu();
            
            
            switch (getch())
            {
            case KEY_UP:
                if(choosingAP.choosen>0) choosingAP.choosen--;
                break;
            case KEY_DOWN:
                if(choosingAP.choosen<choosingAP.args.size()-1) choosingAP.choosen++;
                break;
            case 10:
                choosen = true;
                break;
            default:
                break;
            } 
            
            if(choosen){
                break;
            }

            printw("CHANNEL - %d",channel);
            refresh();

            try
            {
                packet = next_packet_timed(this);
            }
            catch(const std::exception& e)
            {
                counter = 0;            
                nextchannel = nextchannel % 12 + 5;
                changeChannel(nextchannel);
                continue;
            }

            if(packet == NULL){
                continue;
            }
            ieee80211_frame* mac_header = (struct ieee80211_frame *)(packet+24);
            ieee80211_beacon_or_probe_resp* beacon = (struct ieee80211_beacon_or_probe_resp*)(packet + 24 + 24);
            
            
            printw("\n%d %s\n",beacon->info_element->len, beacon->info_element->ssid);
            refresh(); 

            u8 ssid_len = beacon->info_element->len;
            
            
            std::string ssid(beacon->info_element->ssid);
            

            ssid = ssid.substr(0,ssid_len);
            choosingAP.add_option(ssid);
            if(find(APs_SSIDs.begin(), APs_SSIDs.end(), ssid)==APs_SSIDs.end()){
                APs_SSIDs.insert(APs_SSIDs.end(),ssid);
                APs.insert(APs.end(), network(ssid, mac_header->addr3, channel));
                
            }   
            else {counter++;} 
        }    
        
        for (size_t i = 0; i < APs.size(); i++)
        {
            if(APs[i].get_ssid() == choosingAP.args[choosingAP.choosen]){
                device::choosed = APs[i];
            }
        }
        pcap_freecode(&fp);
        clear();

        refresh(); 
        endwin();
        printf("==CHOOSEN== \r\nSSID - %s\r\nMAC - %s\r\nCHANNEL - %d\r\n",
            choosed.get_ssid().c_str(),
            choosed.get_bssid().c_str(),
            choosed.get_channel());
        printf("On %s\r\n",getDevice().c_str());
        //refresh();
    }
}


