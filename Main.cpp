#include <stdio.h>
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32.lib")
#define IP_HDRINCL      2 /* header is included with data */



/* IP头结构 */
typedef struct IP_HEADER {
	unsigned char h_lenver; //4位首部长度+4位IP版本号 
	unsigned char tos; //8位服务类型TOS 
	unsigned short total_len; //16位总长度（字节） 
	unsigned short ident; //16位标识 
	unsigned short frag_and_flags; //3位标志位 
	unsigned char ttl; //8位生存时间 TTL 
	unsigned char proto; //8位协议 (TCP, UDP 或其他) 
	unsigned short checksum; //16位IP首部校验和 
	unsigned int sourceIP; //32位源IP地址 
	unsigned int destIP; //32位目的IP地址 
}IP_HEADER;

/*Ping*/
typedef struct _ping
{
	UCHAR i_type;//8位类型
	UCHAR i_code;//8位代码
	USHORT i_chksum;//16位ICMP校验和
	USHORT i_identify;//16位标志位
	USHORT i_seqnum;//16位序号
	ULONG    i_timestamp;//32位时间戳
	UCHAR i_data[32];//32BYTE选项数据
}PingHeader, *pPingHeader;










/* 校验和 */
USHORT checksum(USHORT *buffer, int size);


/* 创建一个ICMP原始套接字 */
SOCKET CreateICMPRawSocket()
{

	return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);  //INVALID_SOCKET  
}
/* 关闭套接字 */
int    CloseRawSocket(SOCKET Socket)
{
	return closesocket(Socket);  //如无错误发生，则closesocket()返回0
}
int    InilatSocket()
{
	WSADATA Wsadata = { 0 };
	return WSAStartup(MAKEWORD(2, 2), &Wsadata);  //成功返回0
}
int    CleadSocket()
{
	return WSACleanup();
}
/*
VOID   FullIpHeader(IP_HEADER *IP,char * SourceIp,char *DesIp)
{
IP->destIP = inet_addr(DesIp);
IP->sourceIP = inet_addr(SourceIp);
IP->proto = IPPROTO_ICMP;
IP->h_lenver=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long)); //高四位IP版本号，低四位首部长度
//IP->total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16位总长度（字节）


}*/
VOID FullIcmp(PingHeader *Ping, unsigned int i)
{
	unsigned int j = 0;

	Ping->i_type = 8;
	Ping->i_code = 0;
	Ping->i_seqnum = (USHORT)i;
	Ping->i_identify = (unsigned short)GetCurrentProcessId();
	Ping->i_timestamp = (unsigned long)GetTickCount();
	for (j = 0; j < 32; j++)
		Ping->i_data[j] = (UCHAR)('a' + j);


	Ping->i_chksum = 0;
	//计算校验和
	Ping->i_chksum = checksum((unsigned short*)Ping, sizeof(PingHeader));





}
int   PingIp(char *IpAddress)
{

	char on = 4000;

	int nCount = 0;

	int RecvLen = 0;

	char RecvBuff[1024] = { 0 };

	SOCKET RawSocket = 0;

	IP_HEADER IPHEADER = { 0 };

	PingHeader ICMP = { 0 };

	SOCKADDR_IN AddrssSocket = { 0 };
	for (nCount = 1; nCount < 5; nCount++)
	{
		InilatSocket();

		RawSocket = CreateICMPRawSocket();
		if (INVALID_SOCKET == RawSocket)  //失败
		{
			printf("创建原始套接字失败\n");
			return -1;
		}
		//设置IP_HDRINCL 选项 我们自己构建IP包
		if (setsockopt(RawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&on, sizeof(int)) < 0)  //失败
		{
			printf("设置IP_HDRINCL失败 错误码%d\n", GetLastError());
			return -1;
		}

		/* 填充地址 */
		AddrssSocket.sin_addr.S_un.S_addr = inet_addr(IpAddress);
		AddrssSocket.sin_family = AF_INET;


		FullIcmp(&ICMP, nCount);

		if (sendto(RawSocket, (char*)&ICMP, sizeof(ICMP), 0, (struct sockaddr*)&AddrssSocket, sizeof(AddrssSocket)) == SOCKET_ERROR)
		{
			printf("\nSend ping packet error: %d \n", WSAGetLastError());
			return -1;
		}
		memset(RecvBuff, 0, 1024);
		RecvLen = sizeof(AddrssSocket);
		if (SOCKET_ERROR == recvfrom(RawSocket, RecvBuff, sizeof(RecvBuff), 0, (struct sockaddr*)&AddrssSocket, &RecvLen))
		{
			int err = WSAGetLastError();
			if (err != 10060)//超时错误不返回
			{
				printf("recv data error: %d ", err);
				goto End;
				return -1;
			}
			else if (err == 0x274c)
				fprintf(stdout, "请求超时.\n ");
			goto End;



		}
		memcpy(&IPHEADER, RecvBuff, sizeof(IPHEADER));
		memcpy(&ICMP, RecvBuff + sizeof(IPHEADER), sizeof(PingHeader));
		AddrssSocket.sin_family = AF_INET;
		AddrssSocket.sin_addr.S_un.S_addr = IPHEADER.sourceIP;



		if (ICMP.i_type == 3)
		{
			switch (ICMP.i_code)
			{
			case 0:
			{
				printf("网络不可达!\n");
				break;
			}
			case 1:
			{
				printf("主机不可达!\n");
				break;
			}
			case 2:
			{
				printf("协议不可达!\n");
				break;
			}
			case 3:
			{
				printf("端口不可达!\n");
				break;
			}
			default:
			{

				break;
			}

			}

		}
		else  printf("Seq:%d From:%s  TTL:%d   Time:%d(ms)  Data:%d(Byte)\n", ICMP.i_seqnum, inet_ntoa(AddrssSocket.sin_addr), IPHEADER.ttl, GetTickCount() - ICMP.i_timestamp, strlen((const char *)ICMP.i_data) - 10);


	End:        CloseRawSocket(RawSocket);
		CleadSocket();



		Sleep(1000);

	}

	/* 接收的是IP结构 + ICMP结构 */
	//memcpy(&IPHEADER,RecvBuff,sizeof(IPHEADER));
	//memcpy(&ICMP,RecvBuff+sizeof(IPHEADER),sizeof(PingHeader));





}




int main(void)
{
	char IpAddress[20] = { 0 };
	system("title MPing By:MiWu");
	system("color 2");



	while (1)
	{
		//fflush(stdin);
		printf("ping ");
		memset(IpAddress, 0, 20);
		scanf("%s", IpAddress); //接收输入IP地址
		 
		PingIp(IpAddress);          //Ping 默认4次

	}

	return 0;
}


//计算检验和 
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	unsigned short answer = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size == 1) {
		*(char *)&answer = *(char *)buffer;
		cksum += answer;
	}
	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);
	return (USHORT)(~cksum);
}