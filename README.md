# NetSniff
Анонимная ретрансляция кадров L2 выбранной точки доступа Wi-Fi.

# Оборудование
Для запуска ретранслятора в соответствующих режимах необходимо:
- 1 сетевой интерфейс - симплексный канал связи
- 2 сетевых интерфейса - полудуплексный канал связи
- 4 сетевых интерфейса - дуплексный канал связи

# Компиляция
  g++ src/main.cpp -o /bin/Debug/main -lpcap -Wpointer-arith -pthread -lncurses -fno-stack-protector

# Для компиляции необходимы библиотеки
- libncurses
- libpcap
