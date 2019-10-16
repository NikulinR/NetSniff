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

/*#define KEY_UP 65
#define KEY_DOWN 66
#define KEY_ENTER 10*/

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
    void getch_rec(char* value); 
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
    clear();
    start_color();
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(3, COLOR_CYAN, COLOR_BLACK);
    printw("============================\n");
    attron(COLOR_PAIR(2));
    printw("%s\n",menu::desc.c_str());
    attron(COLOR_PAIR(1));
    printw("============================\n");
    for (size_t i = 0; i < menu::args.size(); i++)
    {
        if (i==menu::choosen){
            attron(COLOR_PAIR(3));
            printw("(*)");
        } 
        else{
            printw("( )");
        }
        printw("%s\n", menu::args[i].c_str());
        attron(COLOR_PAIR(1));
    }   
    printw("============================\n");
    refresh();
}

string menu::listen(bool started = true){
    bool done = false;
    int i_input = 0;
    initscr();
    timeout(600);
    keypad(stdscr, true); 
    while(!done){    
        menu::render_menu();  

        i_input = getch();
        switch (i_input)
        {
        case KEY_UP:
            if(menu::choosen>0) menu::choosen--;
            break;

        case KEY_DOWN:
            if(menu::choosen<menu::args.size()-1) menu::choosen++;
            break;

        case 10:
            done = true;
            break;
        
        default:
            break;
        } 
         
    }
    refresh(); clear();
    endwin();
    return menu::args[menu::choosen];
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

