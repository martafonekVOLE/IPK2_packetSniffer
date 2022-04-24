#include <stdio.h>				
#include <signal.h>				
#include <stdlib.h> 		
#include <stdbool.h>	
#include <ctype.h>					
#include <string.h>										
#include <getopt.h>										
#include <time.h>										
#include <sys/types.h>			
#include <netdb.h>				
#include <arpa/inet.h>									
#include <pcap.h>										
#include <netinet/ip.h>			
#include <netinet/tcp.h>								
#include <netinet/udp.h>								
#include <netinet/if_ether.h>	
#include <netinet/ip6.h> 
#include <net/if.h>
#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
using namespace std;
using namespace std::chrono;

// Globals
    // Flags:
    bool interfaceFLAG = false;
    bool portFLAG = false;
    bool tcpFLAG = false;
    bool udpFLAG = false;
    bool arpFLAG = false;
    bool icmpFLAG = false;
    bool nFLAG = false;
    bool allFLAG = false;


    //Important variables
    char *interface = NULL;
    int portno;
    int n = 1;
    int totalBytes = 0;
    
    ether_header *eptr;

    void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
    void listInterface();
    void printData(const u_char *payload, int len);
    void hexIt(const u_char *payload, int len, int offset);
    string timeIs();

int main(int argc, char *argv[]){

    for(int i = 1; i < argc; i++){

        if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0){
            if(interfaceFLAG == true){
                //fault argument
                exit(1);
            }
            if(argc >= (i + 2)){
                interface = (argv[i+1]); 
            }
            else{
            }

            if(argc >= (i + 2)){
                // not required param
                if(strchr(interface, '-')){
                    interfaceFLAG = false;
                }
                else{
                    interfaceFLAG = true;
                    i++;
                }
            }
            else{
                interfaceFLAG = false;
            }

        }

        else if(strcmp(argv[i], "-p") == 0){
            if(portFLAG == true){
                //fault argument
                exit(1);
            }
            if(int(argc) >= int(i + 2)){
                portFLAG = true;    
                portno = atoi(argv[i + 1]);
                i++;
            }
            else{
                exit(99);
            }
        }

        else if(strcmp(argv[i], "-t") == 0 || (strcmp(argv[i], "--tcp") == 0)){
            tcpFLAG = true;
        }

        else if(strcmp(argv[i], "-u") == 0 || (strcmp(argv[i], "--udp") == 0)){
            udpFLAG = true;
        }

        else if((strcmp(argv[i], "--arp") == 0)){
            arpFLAG = true;
        }

        else if((strcmp(argv[i], "--icmp") == 0)){
            icmpFLAG = true;
        }

        else if((strcmp(argv[i], "-n") == 0)){
            nFLAG = true;
            if(argc >= (i + 2)){
                n = atoi(argv[i + 1]);
            }
            else{
                exit(99);
            }
        }

        else{
            if(strcmp(argv[i-1], "-i") == 0 ||strcmp(argv[i-1], "--interface") == 0 || strcmp(argv[i-1], "-p") == 0 || strcmp(argv[i-1], "-n") == 0){
                //if(strcmp(argv[i-1], "-i") == 0 ||strcmp(argv[i-1], "--interface") == 0 ){ check if i is valid interface
                //}
            }
            else{
                exit(99);
            }
        }
    }  

    // Checking arguments
    if(interfaceFLAG == false || (interfaceFLAG == true && interface == NULL)){
        listInterface();
        exit(0);
    }

    if(icmpFLAG == false && arpFLAG == false && udpFLAG == false && tcpFLAG == false){
        allFLAG = true;
        icmpFLAG = true;
        arpFLAG = true;
        udpFLAG = true;
        tcpFLAG = true;
    }

	bpf_u_int32 Mask;             
	bpf_u_int32 Net;             

    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_lookupnet(interface, &Net, &Mask, errbuf) == -1){
        exit(1);
    }

    pcap_t *snifferOpened = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(snifferOpened == NULL){
        exit(1);
    }


    pcap_loop(snifferOpened, -1, process_packet, NULL);
        //-1, because I have my own counter 

    pcap_close(snifferOpened);
    exit(0);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    if(totalBytes == n){
        exit(0);
    }

    eptr = (ether_header*)buffer;

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){

        sockaddr_in source,dest;

        auto *iph = (iphdr*)(buffer + 14);
        int ipHeaderLen = iph->ihl * 4;

        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;

        switch(iph->protocol){
            case 1:  //ICMP Protocol
                if(icmpFLAG == true){

                    std::cout << timeIs() << "\n";

                    // MAC adress
                    struct ethhdr *eth = (struct ethhdr *)buffer;
                    fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                    fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
                
                    // frame length
                    std::cout << "frame length: " << header->caplen <<" bytes\n";
                
                    // IP adress
                    std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                    std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n\n";
                
                    totalBytes++; 

                    if((header->caplen) > 0){
                        printData(buffer, header->caplen);
                    }

                    }
                break;

            case 6:  //TCP Protocol

                if(tcpFLAG == true){
                    auto *tcpheader = (tcphdr*)(buffer + ipHeaderLen + 14);

                    if(portFLAG == true){

                        if(portno == ntohs(tcpheader->dest) || portno == ntohs(tcpheader->source)){
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            // frame length
                            std::cout << "frame length: " << header->caplen <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";
                            totalBytes++;
                            if(header->caplen > 0){
                                printData(buffer, header->caplen);
                            }
                        }
                        else{

                        }
                        
                    }
                    else{
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            // frame length
                            std::cout << "frame length: " << header->caplen <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";
                            totalBytes++;
                            if(header->caplen > 0){
                                printData(buffer, header->caplen);
                            }
                        }

                }
                break;
            case 17: //UDP Protocol
                if(udpFLAG == true){

                    auto *udpheader = (udphdr *) (buffer + ipHeaderLen + 14);

                    if(portFLAG == true){
                        if(portno == ntohs(udpheader->dest) || portno == ntohs(udpheader->source)){
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            // frame length
                            std::cout << "frame length: " << header->caplen <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(udpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(udpheader->dest) << "\n\n";
                            totalBytes++;
                            if((header->caplen) > 0){
                                printData(buffer, header->caplen);
                            }
                        }
                    }
                    else{
                        std::cout << timeIs() << "\n";

                        // MAC adress
                        struct ethhdr *eth = (struct ethhdr *)buffer;
                        fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                        fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                        // frame length
                        std::cout << "frame length: " << header->caplen <<" bytes\n";
                    
                        // IP adress
                        std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                        std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                    
                        // port
                        std::cout << "src port: " << ntohs(udpheader->source) << "\n";
                        std::cout << "dst port: " << ntohs(udpheader->dest) << "\n\n";
                        totalBytes++;
                        if((header->caplen) > 0){
                            printData(buffer, header->caplen);
                        }
                    }
                }
                break;
            
            
            default: 
                break;  
        }   
    }
    else if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6){
        auto *ipHeader = (ip6_hdr *)(buffer + 14);
        int ipHeaderLen = 40;
        sockaddr_in6 source, dest;

        source.sin6_addr = ipHeader->ip6_src;
        dest.sin6_addr = ipHeader->ip6_dst;

        char srcstring[INET6_ADDRSTRLEN];
        char dststring[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &source.sin6_addr, srcstring, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &dest.sin6_addr, dststring, INET6_ADDRSTRLEN);

        uint8_t protocol = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        if (protocol == 0){
            ipHeaderLen = 48;
            protocol = *(uint8_t*)(buffer + 40);
        }

        switch(protocol){
            //ICMPv6
            case 58:
                if(icmpFLAG == true){
                     //MAC
                    struct ethhdr *eth = (struct ethhdr *)buffer;
                    fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                    fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                    cout << timeIs() << "\n";
                    cout << "src IP: " << srcstring << "\n";
                    cout << "dst IP: " << dststring << "\n";

                    cout << "frame length: " << header->caplen << " bytes\n";
                    totalBytes++;

                    if(header->caplen > 0){
                        printData(buffer, header->caplen);
                    }
                }
                break;
            //TCP
            case 6: 
                if(tcpFLAG == true){
                    auto *tcpheader = (tcphdr *)(buffer + 14 + ipHeaderLen);

                    if(portFLAG == true){
                        if(portno == ntohs(tcpheader->dest) || portno == ntohs(tcpheader->source)){
                            //MAC
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            cout << timeIs() << "\n";
                            cout << "src IP: " << srcstring << "\n";
                            cout << "dst IP: " << dststring << "\n";

                            cout << "frame length: " << header->caplen << " bytes\n";

                            std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";
                            totalBytes++;
                            if(header->caplen > 0){
                                printData(buffer, header->caplen);
                            }
                        }
                    }
                    else{
                        //MAC
                        struct ethhdr *eth = (struct ethhdr *)buffer;
                        fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                        fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                        cout << timeIs() << "\n";
                        cout << "src IP: " << srcstring << "\n";
                        cout << "dst IP: " << dststring << "\n";

                        cout << "frame length: " << header->caplen << " bytes\n";

                        std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                        std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";             
                        totalBytes++;
                        if(header->caplen > 0){
                            printData(buffer, header->caplen);
                        }
                    }

                }
                break;
            //UDP
            case 17: 
                if(udpFLAG == true){
                    auto *udpheader = (udphdr *)(buffer + 14 + ipHeaderLen);

                    if(portFLAG == true){
                        if(portno == ntohs(udpheader->dest) || portno == ntohs(udpheader->source)){
                            //MAC
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            cout << timeIs() << "\n";
                            cout << "src IP: " << srcstring << "\n";
                            cout << "dst IP: " << dststring << "\n";

                            cout << "frame length: " << header->caplen << " bytes\n";

                            std::cout << "src port: " << ntohs(udpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(udpheader->dest) << "\n\n";
                            totalBytes++;
                            if((header->caplen) > 0){
                                printData(buffer, header->caplen);
                            }
                        }
                    }
                    else{
                        //MAC
                        struct ethhdr *eth = (struct ethhdr *)buffer;
                        fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                        fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                        cout << timeIs() << "\n";
                        cout << "src IP: " << srcstring << "\n";
                        cout << "dst IP: " << dststring << "\n";

                        cout << "frame length: " << header->caplen << " bytes\n";

                        std::cout << "src port: " << ntohs(udpheader->source) << "\n";
                        std::cout << "dst port: " << ntohs(udpheader->dest) << "\n\n";
                        totalBytes++;
                        if((header->caplen) > 0){
                            printData(buffer, header->caplen);
                        }
                    }

                }
                break;

            default:
                break;
            
        }

    }
    else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
        if(arpFLAG == true){
            cout << timeIs() << "\n";
            cout << "src MAC: ";
            const u_char *ch = buffer + 6;
            for(int i = 0; i < 6; i++){
                if(i!=5){
                    printf("%02x:", *ch);
                }else{
                    printf("%02x", *ch);
                }
                ch++;
            }
            cout << "\ndst MAC: ";

            const u_char *k = buffer;
            for(int i = 0; i < 6; i++){
                if(i!=5){
                    printf("%02x:", *k);
                }else{
                    printf("%02x", *k);
                }
                k++;
            }
            cout << endl << "frame length: " << header->caplen <<" bytes";
            cout << endl << endl;
            if(header->caplen > 0){
                printData(buffer, header->caplen);
            }
            totalBytes++;
        }
    }   
}

void printData(const u_char *payload, int len){
    const u_char *addr = payload;
    int offset = 0;
    int lineRest = len;
    int thisLineLength;
    // print solo
    if (len < 16){
        hexIt(addr, len, offset);
    }else{
        // loop 
        while(true){
            thisLineLength = 16 % lineRest;
            hexIt(addr, thisLineLength, offset);
            lineRest = lineRest - thisLineLength;
            addr = addr + thisLineLength;
            offset += 16;
            if(lineRest <=16){
                hexIt(addr, lineRest, offset);
                break;
            }
        }
    }

    cout << std::endl;
}

void hexIt(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *paylo;

    // print offset
    printf("0x%04x  ", offset);
    
    // if possible, print hex
    paylo = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *paylo);
        paylo++;
        if (i == 7)
            printf(" ");
    }
    // aditional space
    if (len < 8)
        printf(" ");

    // shorter line
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    // ASCII/dot conversion
    paylo = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*paylo))
            printf("%c", *paylo);
        else
            printf(".");
        paylo++;
    }
    cout << std::endl;
}

// Outprint available interface
void listInterface(){
    struct if_nameindex *if_nidxs, *intf;
    if_nidxs = if_nameindex();
    if ( if_nidxs != NULL )
    {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
        {
            printf("%s\n", intf->if_name);
        }

        if_freenameindex(if_nidxs);
    }
} 

string timeIs()
{
 time_t now;
  time(&now);
  struct tm *p = localtime(&now);
  char buf[100];
  size_t len = strftime(buf, sizeof buf - 1, "%FT%T%z", p);

    const auto millis = time_point_cast<milliseconds>(system_clock::now()) - time_point_cast<seconds>(time_point_cast<milliseconds>(system_clock::now()));
    string out;

  if (len > 1) {
    char minute[] = { buf[len-2], buf[len-1], '\0' };
    sprintf(buf + len - 2, ":%s", minute);
    char temp1[20];
    char fuk[6];
    int j = 0;
    for (int i = 0; i < 26; i++){
        if(i < 19){
           temp1[i] = buf[i];  
        }
    }
    for(int i = 19; i < 24; i++){
        fuk[j] = buf[i];
        j++;
    }
    string toOut;
    toOut.append(fuk);
    toOut.append("0");

    long test = millis.count();
    string num_str = to_string(test);

    out.append("timestamp: ");
    out.append(temp1);
    out.append(".");
    out.append(num_str);
    out.append(toOut);

  }
  return(out);
}
