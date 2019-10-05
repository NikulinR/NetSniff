#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>

#include <pcap.h>
#include "ieee80211.h"

#include <string>
#include <string.h>
#include <vector>
#include <bitset>
#include <map>

#include <net/ethernet.h> //for __u8
#include <termios.h>      //for getch() implimentation



#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"

#define KEY_UP 65
#define KEY_DOWN 66
#define KEY_ENTER 10


/*struct ssid_bssid_pair
{
    std::string ssid;
    __u8 bssid[ETH_ALEN];
};

std::vector<ssid_bssid_pair> available_ssid; //pairs of <SSID,BSSID>*/

std::map<std::string, __u8(*)[ETH_ALEN]> available_ssid;


//returns code of a pressed button
char getch() {
    char buf = 0;
    struct termios old = { 0 };
    fflush(stdout);
    if (tcgetattr(0, &old) < 0) perror("tcsetattr()");
    old.c_lflag    &= ~ICANON;   // local modes = Non Canonical mode
    old.c_lflag    &= ~ECHO;     // local modes = Disable echo. 
    old.c_cc[VMIN]  = 1;         // control chars (MIN value) = 1
    old.c_cc[VTIME] = 0;         // control chars (TIME value) = 0 (No time)
    if (tcsetattr(0, TCSANOW, &old) < 0) perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0) perror("read()");
    old.c_lflag    |= ICANON;    // local modes = Canonical mode
    old.c_lflag    |= ECHO;      // local modes = Enable echo. 
    if (tcsetattr(0, TCSADRAIN, &old) < 0) perror ("tcsetattr ~ICANON");
    return buf;
 }

//returns count of available devices for pick-up
int getDevListSize(pcap_if_t devs)
{
    int res = 0;
    pcap_if_t *current = &devs;
    while(current != NULL)
    {
        current = current->next;
        res++;
    }
    return res;
}

//returns list of available devices
void getDevListNames(char *array[], pcap_if_t *devs)
{
    int size = getDevListSize(*devs);
    //printf("%d",size);
    pcap_if_t *current = devs;
    for (size_t i = 0; i < size; i++)
    {
        array[i] = current->name;
        current = current->next;
    }
    
}

//rendering menu via terminal
void PrintMenu(int count, char *args[], int chosen=0, char *desc = ""){
    printf("============================\n");
    printf(KGRN);
    printf("%s\n",desc);
    printf(KNRM);
    printf("============================\n");
    for (size_t i = 0; i < count; i++)
    {
        i==chosen ? printf(KCYN "(*)") : printf("( )");
        printf(" %s\n", args[i]);
        printf(KNRM);
    }   
    printf("============================\n");
}

std::string macToString(__u8 mac[6]){
    std::string res = std::string();
    char buf[18];
    int isDone = snprintf(buf, 
                       sizeof(buf), 
                       "%02x:%02x:%02x:%02x:%02x:%02x\n",
                       (unsigned char) mac[0],
                       (unsigned char) mac[1],
                       (unsigned char) mac[2],
                       (unsigned char) mac[3],
                       (unsigned char) mac[4],
                       (unsigned char) mac[5]);  
    res = buf;
    return res;
}

void set_channel(char *dev, int channel){
    if(channel>0 && channel<13){
        std::string command = std::string();
        char buf[100];
        int isDone = snprintf(buf, 
                        sizeof(buf), 
                        "iwconfig %s channel %d",
                        dev, channel);  
        command = buf;
        system(command.c_str());
    }
}

void change_channel(char *dev, int current = 1){
    
}

std::vector <int> getFC_INFO(__u16 fc){
    printf("===FC INT VALUE===\n%d\n",fc);
    std::vector <int> data;
    int rem = 0;
    while(fc>0)
    {
        rem = fc%2;
        fc/=2;
        data.insert(data.begin(), rem);
    }
    while(data.size() < 16){
        data.insert(data.end(), 0);
    }
    return data;
}

void printFC_INFO(std::vector <int> fc_data){
    //printf("%d", mac_header->fc.fromDS.to_ullong());
    printf("Prortocol - %d%d\n", fc_data[6], fc_data[7]);
    printf("Type -      %d%d\n", fc_data[4], fc_data[5]);
    printf("Subtype -   %d%d%d%d\n", fc_data[0], fc_data[1], fc_data[2], fc_data[3]);
    
    printf("To DS -     %d\n", fc_data[15]);
    printf("From DS -   %d\n", fc_data[14]);
    printf("More Frags- %d\n", fc_data[13]);
    printf("Retry-      %d\n", fc_data[12]);

    printf("Power mgmt- %d\n", fc_data[11]);
    printf("More Data-  %d\n", fc_data[10]);
    printf("WEP-        %d\n", fc_data[9]);
    printf("Order-      %d\n", fc_data[8]);

    printf("\n");
}

void testFC_INFO(){
    for (size_t i = 0; i < 100; i++)
    {
        std::vector <int> fc_data = getFC_INFO(i);
        for (size_t j = 0; j < fc_data.size(); j++)
            printf("%d",fc_data[j]);
        printf("\n");        
    }    
}



void callbackWIFI(u_char *arg, 
                  const struct pcap_pkthdr* pkthdr, 
                  const u_char* packet){
    ieee80211_frame* mac_header = (struct ieee80211_frame *)(packet+24);
    std::vector<int> fc_data = getFC_INFO(mac_header->fc);
    //printFC_INFO(fc_data);
    bool isBeacon = (mac_header->fc == 128);
    if (isBeacon){
        printf("\n=======================\n");
        ieee80211_beacon_or_probe_resp* beacon = (struct ieee80211_beacon_or_probe_resp*)(packet + 24 + 24);
        
        u8 ssid_len = beacon->info_element->len;
        std::string ssid(beacon->info_element->ssid);
        ssid = ssid.substr(0,ssid_len);
        ///!!!разделить ssid и rates!!!
        printf("Beacon from %s\n",ssid.c_str());
        
        if(available_ssid.find(ssid) == available_ssid.end())
            available_ssid.insert(std::pair<std::string, __u8(*)[ETH_ALEN]>(ssid, &mac_header->addr3));
        else{
            
        }
        for(auto var : available_ssid)
        {
            printf("\nSSID:  %s\nBSSID: %s\n", var.first.c_str(), macToString(*(var.second)).c_str());
        }

        /*ssid_bssid_pair pair = {ssid, *mac_header->addr1};
        available_ssid.insert(available_ssid.begin(), pair);*/
    }
}

int main(int argc, char const *argv[])
{
    
    char *errbuf = new char[PCAP_ERRBUF_SIZE];
    
    /*===================================================
    ===================CHOOSING DEVICE===================
    ===================================================*/
    
    //get list of available devices for pick-up
    pcap_if_t *alldevs;    
    char *dev;
    pcap_findalldevs(&alldevs, errbuf);
    int dev_list_size = getDevListSize(*alldevs);
    char *args[dev_list_size];
    getDevListNames(args, alldevs);

    int choosen = 0;

    char *str_choose_dev = "Please choose target device:";

    PrintMenu(dev_list_size, args, choosen, str_choose_dev);
    bool menuChoosing = true;
    
    int i_input;

    //rendering menu
    while(menuChoosing)
    {        
        i_input = getch();
        system("clear");
        switch (i_input)
        {
        case KEY_UP:
            if(choosen>0) choosen--;
            PrintMenu(dev_list_size, args, choosen, str_choose_dev);
            break;
        case KEY_DOWN:
            if(choosen<dev_list_size-1) choosen++;
            PrintMenu(dev_list_size, args, choosen, str_choose_dev);
            break;
        case KEY_ENTER:
            printf("You choosed %s\n",args[choosen]);
            dev = args[choosen];
            menuChoosing = false;
            break;
        default:
            break;
        }
    }
    
    //activating device
    pcap_t *handle = pcap_create(dev, errbuf);
	pcap_set_rfmon(handle, 1);
	pcap_set_promisc(handle, 1); /* Capture packets that are not yours */
	pcap_set_snaplen(handle, 2048); /* Snapshot length */
	pcap_set_timeout(handle, 1000); /* Timeout in milliseconds */
	pcap_activate(handle);

    /**
     * 1 Beacon checking
     * 2 Adding SSID and MAC to dictionary if not exist
     * 3 Rendering menu (Output - mac_dict[SSID])
     * */
    
    

    /*===================================================
    ==================SCANNING NETWORK===================
    ===================================================*/
    
    



    //!!!смена каналов!!!
    pcap_loop(handle, -1, callbackWIFI, NULL);
    

    /*===================================================
    ====================CHOOSING SSID====================
    ===================================================*/


    /*===================================================
    ================WRITE TO FILE / VIEW=================
    ===================================================*/


    /*===================================================
    =====================TRANSLATING=====================
    ===================================================*/

    
    return 0;
}
