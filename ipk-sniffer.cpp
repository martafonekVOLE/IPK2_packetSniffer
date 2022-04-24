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
using namespace std;
using namespace std::chrono;

struct sockaddr_in source,dest;

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
    int n = 10;
    int totalBytes = 0;
    std::string outFile = "";
    
    ether_header *eptr;

    void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
    void listInterface();
    void printICMP(const u_char * Buffer, int Size);
    void printTCP(const u_char * Buffer, int Size, bool ipv6FLAG);
    void printUDP(const u_char * Buffer, int Size);
    string timeIs();

int main(int argc, char *argv[]){
    //pcap things

    for(int i = 1; i < argc; i++){


        if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0){
            if(interfaceFLAG == true){
                //chyba argumentu
                exit(1);
            }
            interface = (argv[i+1]); 

            if(argc > (i + 1)){
                // volitelný parametr
                if(strchr(interface, '-')){
                    interfaceFLAG = false;
                }
                else{
                    interfaceFLAG = true;
                }
            }
            else{
                interfaceFLAG = false;
            }

        }

        else if(strcmp(argv[i], "-p") == 0){
            if(portFLAG == true){
                //chyba argumentu
                exit(1);
            }
            portFLAG = true;
            portno = atoi(argv[i + 1]);
        }

        else if(strcmp(argv[i], "-t") == 0 || (strcmp(argv[i], "--tcp") == 0)){
            tcpFLAG = true;
        }

        else if(strcmp(argv[i], "-u") == 0 || (strcmp(argv[i], "--udp") == 0)){
            udpFLAG = true;
        }

        else if((strcmp(argv[i], "-arp") == 0)){
            arpFLAG = true;
        }

        else if((strcmp(argv[i], "--icmp") == 0)){
            icmpFLAG = true;
        }

        else if((strcmp(argv[i], "-n") == 0)){
            nFLAG = true;
            n = atoi(argv[i + 1]);
        }

        else{

        }
    }  

    // Práce s argumenty
    if(interfaceFLAG == false || (interfaceFLAG == true && interface == NULL)){
        listInterface();
        return 0;
    }

    if(icmpFLAG == false && arpFLAG == false && udpFLAG == false && tcpFLAG == false){
        allFLAG = true;
    }

    // TIMESTAMP
    // time_t rawtime;
    // struct tm * timeinfo;
    // char finalTime [80];

    // time (&rawtime);
    // timeinfo = localtime (&rawtime);

    // strftime (finalTime,80,"%Y-%m-%dT%H:%M:%S",timeinfo);
    // puts (finalTime); 

    struct bpf_program fp;         
	bpf_u_int32 Mask;             
	bpf_u_int32 Net;             

    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_lookupnet(interface, &Net, &Mask, errbuf) == -1){
        //TODO chyba
        return(1);
    }

    pcap_t *snifferOpened = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(snifferOpened == NULL){
        return(1);
    }


    pcap_loop(snifferOpened, n, process_packet, NULL);
        //-1 nahradit Nkem????

    pcap_close(snifferOpened);
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    eptr = (ether_header*)buffer;

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){

        auto *iph = (iphdr*)(buffer + 14);
        int ipHeaderLen = iph->ihl * 4;

        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;

        switch(iph->protocol){
            case 1:  //ICMP Protocol
                if(icmpFLAG == true){

                    auto *icmpheader = (tcphdr*)(buffer + 14 + ipHeaderLen);
                    int icmpHeaderSize = sizeof(icmpheader) + 14 + ipHeaderLen;

                    const u_char *payload = (u_char*)(buffer + icmpHeaderSize);
                    int sizePayload = ntohs(iph->tot_len) - icmpHeaderSize;

                    if(portFLAG == true){
                        if(portno == ntohs(icmpheader->dest) || portno == ntohs(icmpheader->source)){
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
                        
                            // frame length
                            std::cout << "frame length: " << ntohs(iph->tot_len) <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(icmpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(icmpheader->dest) << "\n\n";
                            totalBytes++;
                        }
                    }
                    else{
                        std::cout << timeIs() << "\n";

                        // MAC adress
                        struct ethhdr *eth = (struct ethhdr *)buffer;
                        fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                        fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
                    
                        // frame length
                        std::cout << "frame length: " << ntohs(iph->tot_len) <<" bytes\n";
                    
                        // IP adress
                        std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                        std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                    
                        // port
                        std::cout << "src port: " << ntohs(icmpheader->source) << "\n";
                        std::cout << "dst port: " << ntohs(icmpheader->dest) << "\n\n";
                        totalBytes++; 
                    }
                    }
                break;		
            case 6:  //TCP Protocol
                if(tcpFLAG == true){
                    auto *tcpheader = (tcphdr*)(buffer + ipHeaderLen + 14);
                    int icmpHeaderSize = tcpheader->doff * 4 + ipHeaderLen + 14;

                    const u_char *payload = (u_char*)(buffer + icmpHeaderSize);
                    int sizePayload = ntohs(iph->tot_len) - icmpHeaderSize;

                    if(portFLAG == true){
                        if(portno == ntohs(tcpheader->dest) || portno == ntohs(tcpheader->source)){
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            // frame length
                            std::cout << "frame length: " << ntohs(iph->tot_len) <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";
                            totalBytes++;
                        }
                        else{
                            std::cout << timeIs() << "\n";

                            // MAC adress
                            struct ethhdr *eth = (struct ethhdr *)buffer;
                            fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
                            fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

                            // frame length
                            std::cout << "frame length: " << ntohs(iph->tot_len) <<" bytes\n";
                        
                            // IP adress
                            std::cout << "src IP: " << inet_ntoa(source.sin_addr) << "\n";
                            std::cout << "dst IP: " << inet_ntoa(dest.sin_addr) << "\n";
                        
                            // port
                            std::cout << "src port: " << ntohs(tcpheader->source) << "\n";
                            std::cout << "dst port: " << ntohs(tcpheader->dest) << "\n\n";
                            totalBytes++;
                        }
                    }
                }
                break;
            case 17: //UDP Protocol
                if(udpFLAG == true){
                    
                }
                totalBytes++;
                break;
            
            
            default: //Other protocols TODO count them to totalBytes?
                if(allFLAG == true){
                    totalBytes++;
                }
                break;  
        }   
    }

    
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

void packetHead(const u_char *Buffer, int Size){
	struct ethhdr *eth = (struct ethhdr *)Buffer;
    
    fprintf(stdout, "src MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
    fprintf(stdout, "dest MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
}

void ipHead(const u_char * Buffer, int Size){

    unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(stdout, "src IP: %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(stdout, "dst IP: %s\n" , inet_ntoa(dest.sin_addr) );
}

// Packet processing




void printUDP(const u_char * Buffer, int Size){
    printf("UDP");
}

string timeIs()
{
    //https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
    const auto millis = time_point_cast<milliseconds>(system_clock::now()) - time_point_cast<seconds>(time_point_cast<milliseconds>(system_clock::now()));
    const auto c_now = system_clock::to_time_t(time_point_cast<seconds>(time_point_cast<milliseconds>(system_clock::now())));

    stringstream ss;
    ss << put_time(gmtime(&c_now), "%FT%T")
       << '.' << setfill('0') << setw(3) << millis.count() << 'Z';
    return ss.str();
}
