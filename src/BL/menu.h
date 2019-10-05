
#include <stdlib.h>
#include <string>
#include <vector>

#include "utils.h"

#include <stdlib.h>
#include <string>

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

using namespace std;

class menu
{
private:
    /* data */
    
    
    string desc;
    bool isFinalized;
    int get_str_list_size(string arr);

public:
    menu(vector<string> args, string desc);
    ~menu();

    int choosen;
    vector<string> args;
    
    void render_menu();
    void add_option(string arg);
    string listen(bool started);    
};

menu::menu(vector<string> args, string desc = "")
{ 
    menu::args = args;
    menu::desc = desc;
    menu::choosen = 0;
    menu::isFinalized = false;
}

menu::~menu()
{
    //delete[] args;
}

void menu::render_menu(){
    printf("============================\n");
    printf(KGRN);
    printf("%s\n",menu::desc.c_str());
    printf(KNRM);
    printf("============================\n");
    for (size_t i = 0; i < menu::args.size(); i++)
    {
        i==menu::choosen ? printf(KCYN "(*)") : printf("( )");
        printf(" %s\n", menu::args[i].c_str());
        printf(KNRM);
    }   
    printf("============================\n");
}

string menu::listen(bool started = true){
    char i_input = 0;
    if(started){
        menu::render_menu();
        started = false;
    }
    i_input = getch();
    system("clear"); 
    switch (i_input)
    {
    case KEY_UP:
        if(menu::choosen>0) menu::choosen--;
        menu::render_menu();
        return menu::listen(started);
        break;
    case KEY_DOWN:
        if(menu::choosen<menu::args.size()-1) menu::choosen++;
        menu::render_menu();
        return menu::listen(started);
        break;
    case KEY_ENTER:
        return menu::args[menu::choosen];
        break;
    default:
        menu::render_menu();
        return menu::listen(started);
        break;
    } 
}

void menu::add_option(string arg){
    bool found = false;
    for (size_t i = 0; i < args.size(); i++){
        if(args[i]==arg){
            found = true;      
        }
    }
    if(!found){
        args.insert(args.end(),arg);
    }
    
    
}