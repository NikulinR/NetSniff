#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

void PrintMenu(int count, char *args[], int chosen=0){
    system("CLS");
    for (size_t i = 0; i < count; i++)
    {
        i==chosen ? printf("(*)") : printf("( )");
        printf(" %s\n", args[i]);
    }   
}

int main(int argc, char const *argv[])
{
    /* code */
    char *args[] = {"01", "12", "23", "34"};
    int size = 4;
    int choosen = 0;
    PrintMenu(size, args, choosen);
    bool menuChoosing = true;
    
    int i_input;

    while(menuChoosing)
    {
        
        i_input = getch();
        switch (i_input)
        {
        case 72:
            if(choosen>0) choosen--;
            PrintMenu(size, args, choosen);
            break;
        case 80:
            if(choosen<size-1) choosen++;
            PrintMenu(size, args, choosen);
            break;
        case 13:
            printf("You choosed %s",args[choosen]);
            menuChoosing = false;
            break;
        default:
            break;
        }
    }
    
    return 0;
}
