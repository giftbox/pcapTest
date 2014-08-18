#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int *id = (int *)arg;

    printf("id: %d\n", ++(*id));
    printf("Pacet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Rcieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    int i;
    for (i = 0; i < pkthdr->len; ++i)
    {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }

    printf("\n\n");
}

int main(int argc, char *argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE], *devStr;
    devStr = pcap_lookupdev(errBuf);

    if (devStr)
    {
        printf("success: device: %s\n", devStr);
    }
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }

    pcap_t *device = pcap_open_live(devStr, BUFSIZ, 1, 0, errBuf);

    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }

    struct bpf_program filter;
    pcap_compile(device, &filter, "icmp", 1, 0);
    pcap_setfilter(device, &filter); 

    int id = 0;
    pcap_loop(device, -1, getPacket, (u_char *)&id);

    pcap_close(device);

    return 0;
}
