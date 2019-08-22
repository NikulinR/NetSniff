#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <pcap.h>

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

void getDevListNames(char *array[], pcap_if_t *devs)
{
    int size = getDevListSize(*devs);
    //printf("%d",size);
    pcap_if_t *current = devs;
    for (size_t i = 0; i < size; i++)
    {
        array[i] = current->name;
        current = current->next;
        /* code */
    }
    
}

void PrintMenu(int count, char *args[], int chosen=0){
    
    for (size_t i = 0; i < count; i++)
    {
        i==chosen ? printf("(*)") : printf("( )");
        printf(" %s\n", args[i]);
    }   
}

int main(int argc, char const *argv[])
{
    /* code */
    char *errbuf = new char[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    pcap_findalldevs(&alldevs, errbuf);
    int dev_list_size = getDevListSize(*alldevs);

    char *args[dev_list_size];
    getDevListNames(args, alldevs);

    int choosen = 0;
    printf("Please choose target device:\n");
    PrintMenu(dev_list_size, args, choosen);
    bool menuChoosing = true;
    
    int i_input;

    while(menuChoosing)
    {
        
        i_input = getch();
        system("clear");

        printf("Please choose target device:\n");
        switch (i_input)
        {
        case 65:
            if(choosen>0) choosen--;
            PrintMenu(dev_list_size, args, choosen);
            break;
        case 66:
            if(choosen<dev_list_size-1) choosen++;
            PrintMenu(dev_list_size, args, choosen);
            break;
        case 10:
            printf("You choosed %s\n",args[choosen]);
            menuChoosing = false;
            break;
        default:
            break;
        }
    }
    
    return 0;
}
