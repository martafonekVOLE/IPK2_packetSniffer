**IPK projekt 2**
*Varianta ZETTA - Sniffer packetů*
*author: Martin Pech (xpechm00)*


Popis programu:

Sniffer packetů - jedná se o program, který sleduje provoz na síti. 
Analyzuje a filtruje packety podle vstupních argumentů (více v manual.pdf).


Přeložení projektu:

Projekt je možné přeložit pomocí nástroje *makefile*.
Příkaz: make

Další cíle: 
make clean - smaže zdrojové soubory
make cleanAll - smaže vše
make run - rozběhne sniffer s argumentem *-i*


Spuštění projektu:

Projekt je možné spustit přes *makefile* s cílem *run*
make run -> vykoná ./ipk-sniffer -i

Další příklady spuštění:
    Zachytí 5 UDP/TCP packetů na daném interface:
    ./ipk-sniffer -i *interface_name* -t -u -n 5
    Zachytí ARP rámce:
    ./ipk-sniffer -i *interface_name* --arp

    Více příkladů v manual.pdf


Seznam odevzdaných souborů:

1. README.md
2. ipk-sniffer.cpp
3. makefile
4. manual.pdf
