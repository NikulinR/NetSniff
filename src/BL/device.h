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

using namespace std;
using namespace std::chrono_literals;

class device
{
private:
    struct bpf_program fp;
    struct pcap_pkthdr header;
    
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
    const u_char *next_packet_timed();
    

public:
    device();
    ~device();
    network choosed;
    vector<string> getDevs() {return available;}
    int getDevCount(){return devCount;}
    string getDevice(){return name;}

    void setDevice(string dev){name = dev;}

    void activateDev();
    void searchAP();
    string *getAPs();
    void changeChannel(int ch);
};

device::device()
{
    pcap_findalldevs(&pcap_dev, errbuf);
    devCount = getDevCount(*pcap_dev);
    getDevListNames(pcap_dev);
    
    menu dev_menu = menu(available, "Please choose target device:");
    name = dev_menu.listen();
    
}

device::~device()
{
    
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

void device::activateDev(){
    handle = pcap_create(name.c_str(), errbuf);
    pcap_set_rfmon(handle, 1);
	pcap_set_promisc(handle, 1); /* Capture packets that are not yours */
	pcap_set_snaplen(handle, 2048); /* Snapshot length */
	pcap_set_timeout(handle, 1000); /* Timeout in milliseconds */
	pcap_activate(handle);
    channel = 1;
    changeChannel(0);
}

void device::changeChannel(int ch){
        ch = ch % 12;
        if(ch == 0) ch = 1;

        char bufdown[100];
        char bufup[100];
        int isDone = snprintf(bufdown, 
                        sizeof(bufdown), 
                        "sudo iw dev %s set channel %d",
                        name.c_str(), ch);  
        system(bufdown);
        channel = ch;    
}

const u_char *device::next_packet_timed()
{
    std::mutex m;
    std::condition_variable cv;
    const u_char *retValue;
    pcap_t *handle_t = handle;
    pcap_pkthdr header_t= header;

    std::thread t([&cv, &retValue, &handle_t, &header_t]() 
    {
        retValue = pcap_next(handle_t, &header_t);
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(cv.wait_for(l, 600ms) == std::cv_status::timeout) 
            throw std::runtime_error("Timeout");
    }

    return retValue;    
}



void device::searchAP(){
    activateDev();
    
    if (pcap_compile(handle, &fp, "type mgt subtype beacon", 0, PCAP_NETMASK_UNKNOWN)==-1){
        printf("%s",pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp)==-1){
        printf("%s",pcap_geterr(handle));
    }
    
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
        if(counter>3){
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
        
        printw("CHANNEL - %d",channel);
        

        //           !!!If can't capture packet in 2seconds, change channel!!!
        try
        {
            packet = next_packet_timed();
        }
        catch(const std::exception& e)
        {
            counter = 0;            
            nextchannel = nextchannel % 12 + 5;
            changeChannel(nextchannel);
            continue;
        }

        ieee80211_frame* mac_header = (struct ieee80211_frame *)(packet+24);
        ieee80211_beacon_or_probe_resp* beacon = (struct ieee80211_beacon_or_probe_resp*)(packet + 24 + 24);
        
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
    clear();

    refresh(); 
    endwin();
    printw("==CHOOSEN== \nSSID - %s\nMAC - %s\nCHANNEL - %d\n",
        choosed.get_ssid().c_str(),
        choosed.get_bssid().c_str(),
        choosed.get_channel());
    printw("On %s\n",getDevice().c_str());
    refresh();
}