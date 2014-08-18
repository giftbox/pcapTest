#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
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

    pcap_dump(arg, pkthdr, packet);
}

int main(int argc, char *argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE], *devStr;
    devStr = pcap_lookupdev(errBuf);

    pcap_if_t *pdev;
    pcap_if_t *alldevs;
    pcap_findalldevs(&alldevs, errBuf);
    for (pdev = alldevs; pdev; pdev = pdev->next)
    {
        printf("%s\n%s\n", pdev->name, pdev->description);
    }

    pcap_t *device = pcap_open_live("can0", BUFSIZ, 1, 0, errBuf);

    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }

    //struct bpf_program filter;
    //pcap_compile(device, &filter, "ether proto 0x88a4", 1, 0);
    //pcap_setfilter(device, &filter); 

    pcap_dumper_t *dumpfp;
    dumpfp = pcap_dump_open(device, "traffic.pcap");
    if (dumpfp == NULL)
    {
        printf("Error on opening output file.\n");
        exit(-1);
    }

    if (pcap_loop(device, 10, getPacket, (u_char *)dumpfp) < 0)
    {
        printf("pcap_loop(): %s\n", pcap_geterr(device));
    }

    pcap_dump_close(dumpfp);
    //pcap_freecode(&filter);
    pcap_close(device);
    pcap_freealldevs(alldevs);

    return 0;
}
