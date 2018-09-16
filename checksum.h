

#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)
#define CARRY 65536

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {
        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;
    }

    result=tempChecksum;
    return result;
}

uint16_t calIPChecksum(uint8_t* data)
{
    struct libnet_ipv4_hdr* iph=(struct libnet_ipv4_hdr*)data;
    iph->ip_sum=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,iph->ip_hl*4);
    iph->ip_sum = htons(checksum^0xffff);//xor checksum

    return checksum;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct libnet_ipv4_hdr *iph=(struct libnet_ipv4_hdr*)data;
    struct libnet_tcp_hdr *tcph=(struct libnet_tcp_hdr*)(data+iph->ip_hl*4);

    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->th_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;

    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->th_sum=checksum;

    return checksum;
}

uint16_t calUDPChecksum(uint8_t *data, int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //save to network byte order
 
    //init Pseudoheader
    struct libnet_ipv4_hdr *iph=(struct libnet_ipv4_hdr*)data;
    struct libnet_udp_hdr *udph=(struct libnet_udp_hdr*)(data+iph->ip_hl*4);
    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));
 
    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));
 
    //Cal TCP Segement Checksum
    udph->uh_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)udph,ntohs(pseudoheader.TCPLen));
 
 
    uint16_t checksum;
    int tempCheck;
 
    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;
 
 
    checksum=ntohs(checksum^0xffff); //xor checksum
    udph->uh_sum=checksum;
 
    return checksum;
}
