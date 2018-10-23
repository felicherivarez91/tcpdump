#include <pcap.h> 
#include <stdlib.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <signal.h>
#include <string.h>

extern void PackAnalyze(register u_char * ,const struct pcap_pkthdr * ,register const u_char * ); //прототип функции анализа пакетов

extern u_int16_t EtherAnalyze(register u_char * , const struct pcap_pkthdr * ,register const u_char * ); //анализ Ethernet-заголовка

extern void EtherARPAnalyze(register u_char * ,const struct pcap_pkthdr * ,register const u_char * );//анализ ARP протокола

extern void IPAnalyze(register u_char * ,const struct pcap_pkthdr * ,register const u_char * ); //анализ IP протокола

extern void Terminate(); //Процедура прерывания бесконечного цикла pcap_loop();

typedef unsigned long long int ull_int;

static ull_int count=0; //счётчик пакетов
static pcap_t * handler=NULL;   //дескриптор сессии прослушивания
static ull_int TCPcount=0;  //счётчик отправленых TCP пакетов
static ull_int UDPcount=0;  //счётчик отправленых UDP пакетов
static int intpar;          // глобальные переменные для параметров
static char ** charpar;     // функции main
static size_t srcMACCountPack=0;
static size_t dstMACCountPack=0;
//---------------------начало главной функции--------------------------
int main(int argc,char * argv[])
{
   
    char * errbuff=NULL;     //буфер для ошибок
    char * device=NULL;      //Имя устройства
    bpf_u_int32 mask,class;  //Хранение настроек IP
    struct bpf_program filstruct; //выражение для фильтра
    char yorn;
    
    intpar=argc;
    charpar=argv;
    errbuff=(char *) malloc(PCAP_ERRBUF_SIZE*sizeof(char));  
    if (!errbuff)
    {
        printf("Возникла ошибка при выделении динамической памяти. Программа аварийно завершилась.\n");
        exit(EXIT_FAILURE);
    }   
    device=pcap_lookupdev(errbuff); //определение сетевого устройства
    if (!device)
    {
        printf("Возникла ошибка: %s.\n",errbuff);
        printf("Программа аварийно завершилась.\n");
        free(errbuff);
        errbuff=NULL;
        exit(EXIT_FAILURE); 
    }
    pcap_lookupnet(device,&class,&mask,errbuff); //определение настроек IP
    if (!class || !mask)
    {
        printf("Невозможно определить ваш IP-адрес и маску сети. Программа аварийно завершилась.\n");
        free(errbuff);
        errbuff=NULL;
        exit(EXIT_FAILURE);    
    };
    handler=pcap_open_live(device,BUFSIZ,1,0,errbuff); //начало сессии прослушивания.
    if (!handler)
    {
        printf("Возникла ошибка с устройством: %s.\n",errbuff);
        printf("Программа аварийно завершилась.\n");
        free(errbuff);
        errbuff=NULL;
        exit(EXIT_FAILURE);
    }
    if (intpar!=2)
    {
        printf("Вы не указали критерии анализа пакетов. Хотите ли вы анализировать все поступающие пакеты?(y - да, n - нет).\n");
        scanf("%c",&yorn);
        if (yorn=='n') return EXIT_SUCCESS;
        pcap_compile(handler,&filstruct,charpar[intpar],0,mask);    
    }
    else
    {
        pcap_compile(handler,&filstruct,charpar[intpar-1],0,mask);  //компиляция фильтра
    }    
    pcap_setfilter(handler,&filstruct);  
    signal(SIGINT,Terminate);   //обработка сигналов
    signal(SIGTSTP,Terminate);
    pcap_loop(handler,-1,PackAnalyze,NULL);
    pcap_close(handler);
    free(errbuff);
    errbuff=NULL;
    fprintf(stdout,"\nКоличество пакетов: %lld.",count);
    if ((intpar==2) && (strstr(charpar[intpar-1],"ether host")!=NULL) )
    {
        fprintf(stdout,"\nКоличество пакетов, которые были отправлены с определённого MAC адреса %s, равно %lu.",charpar[intpar-1]+11,srcMACCountPack); 
        fprintf(stdout,"\nКоличество пакетов, которые были отправлены на определённый MAC адрес %s, равно %lu.",charpar[intpar-1]+11,dstMACCountPack);
    }
    fprintf(stdout,"\nКоличество TCP пакетов: %lld.",TCPcount);
    fprintf(stdout,"\nКоличество UDP пакетов: %lld.\n",UDPcount);
    return EXIT_SUCCESS;  
} 
//-----------конец главной функции------------------------------------

//-----------функция анализа пакетов---------------------------------------------------------
void PackAnalyze(register u_char *args,const struct pcap_pkthdr *header,register const u_char *packet)
{
   
    u_int16_t ether_head;

    printf("Пакет №%lld: ",++count);
    ether_head=EtherAnalyze(args,header,packet);
    if (ether_head==ETHERTYPE_ARP) EtherARPAnalyze(args,header,packet);
    else if (ether_head==ETHERTYPE_IP) IPAnalyze(args,header,packet);
    else fprintf(stdout,"Неопознанный протокол.\n\n");
}
//------------------конец функции--------------------------------------------------
u_int16_t EtherAnalyze(register u_char *args,const struct pcap_pkthdr *header,register const u_char *packet)
{
    
    struct ether_header * ethernet;

    ethernet=(struct ether_header * ) packet;
    printf("MAC адрес отправителя: %s, ",ether_ntoa((struct ether_addr *) ethernet->ether_shost));
    printf("MAC адрес получателя: %s, ",ether_ntoa((struct ether_addr *) ethernet->ether_dhost));
    if (intpar==2)
       if (strstr(charpar[intpar-1],"ether host")!=NULL)
       {
           if (strcmp(ether_ntoa((struct ether_addr *) ethernet->ether_shost),charpar[intpar-1]+11)==0)
               srcMACCountPack++; 
           else
           if (strcmp(ether_ntoa((struct ether_addr *) ethernet->ether_dhost),charpar[intpar-1]+11)==0) 
               dstMACCountPack++; 
       }
    return ntohs(ethernet->ether_type);
}

void EtherARPAnalyze(register u_char * args,const struct pcap_pkthdr * header,register const u_char * packet)
{

    struct ether_arp * ARP;
    struct in_addr addr;

    printf("Тип протокола: ARP, ");
    ARP=(struct ether_arp * ) packet;
    addr.s_addr=*ARP->arp_spa;
    printf("IP адрес отправителя: %s, ",inet_ntoa(addr));
    addr.s_addr=*ARP->arp_tpa;
    printf("IP адрес получателя: %s\n\n",inet_ntoa(addr));
}

void IPAnalyze(register u_char * args,const struct pcap_pkthdr * header,register const u_char * packet)
{
 
    const struct ip * IP;
 
    fprintf(stdout,"Тип протокола: IP, ");
    IP=(struct ip *)(packet+sizeof(struct ether_header));
    printf("IP адрес отправителя: %s ,", inet_ntoa(IP->ip_src));
    printf("IP адрес получателя: %s\n\n", inet_ntoa(IP->ip_dst));
    if(IP->ip_p==IPPROTO_TCP)
       TCPcount++; 
    else if(IP->ip_p==IPPROTO_UDP)
       UDPcount++;
}

void Terminate()
{
    pcap_breakloop(handler);//функция выхода из цикла pcap_loop.
}
