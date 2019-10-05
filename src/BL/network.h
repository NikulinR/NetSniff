#include <stdlib.h>
#include <string>
#include <net/ethernet.h>
#include <pcap.h>

using namespace std;

class network
{
private:
    string ssid;
    __u8 *bssid;
    int channel;
    char *errbuf = new char[PCAP_ERRBUF_SIZE];
public:
    network(string ssid, __u8 *bssid, char channel);
    ~network();
    
    string get_ssid(){return ssid;};
    string get_bssid();
    void get_bssid_raw(__u8[]);
    int get_channel(){return channel;};
    
    void set_ssid(string ssid);
    void set_bssid(string bssid);
    void set_bssid_raw(__u8[]);
    void set_channel(int channel);

    void copmare_ssid_to_bssid();
    void translate();
};

network::network(string ssid, __u8 *bssid, char channel)
{
    network::ssid = ssid;
    network::bssid = bssid;
    network::channel = channel;
}

network::~network()
{
}

string network::get_bssid(){
    string res;
    char buf[19];
    int isDone = snprintf(buf, 
                       sizeof(buf), 
                       "%02x:%02x:%02x:%02x:%02x:%02x\n",
                       (unsigned char) bssid[0],
                       (unsigned char) bssid[1],
                       (unsigned char) bssid[2],
                       (unsigned char) bssid[3],
                       (unsigned char) bssid[4],
                       (unsigned char) bssid[5]);  
    res = buf;
    return res;
}

    