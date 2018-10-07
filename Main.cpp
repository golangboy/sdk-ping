#include <stdio.h>
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32.lib")
#define IP_HDRINCL      2 /* header is included with data */



/* IPͷ�ṹ */
typedef struct IP_HEADER {
	unsigned char h_lenver; //4λ�ײ�����+4λIP�汾�� 
	unsigned char tos; //8λ��������TOS 
	unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ� 
	unsigned short ident; //16λ��ʶ 
	unsigned short frag_and_flags; //3λ��־λ 
	unsigned char ttl; //8λ����ʱ�� TTL 
	unsigned char proto; //8λЭ�� (TCP, UDP ������) 
	unsigned short checksum; //16λIP�ײ�У��� 
	unsigned int sourceIP; //32λԴIP��ַ 
	unsigned int destIP; //32λĿ��IP��ַ 
}IP_HEADER;

/*Ping*/
typedef struct _ping
{
	UCHAR i_type;//8λ����
	UCHAR i_code;//8λ����
	USHORT i_chksum;//16λICMPУ���
	USHORT i_identify;//16λ��־λ
	USHORT i_seqnum;//16λ���
	ULONG    i_timestamp;//32λʱ���
	UCHAR i_data[32];//32BYTEѡ������
}PingHeader, *pPingHeader;










/* У��� */
USHORT checksum(USHORT *buffer, int size);


/* ����һ��ICMPԭʼ�׽��� */
SOCKET CreateICMPRawSocket()
{

	return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);  //INVALID_SOCKET  
}
/* �ر��׽��� */
int    CloseRawSocket(SOCKET Socket)
{
	return closesocket(Socket);  //���޴���������closesocket()����0
}
int    InilatSocket()
{
	WSADATA Wsadata = { 0 };
	return WSAStartup(MAKEWORD(2, 2), &Wsadata);  //�ɹ�����0
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
IP->h_lenver=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long)); //����λIP�汾�ţ�����λ�ײ�����
//IP->total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16λ�ܳ��ȣ��ֽڣ�


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
	//����У���
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
		if (INVALID_SOCKET == RawSocket)  //ʧ��
		{
			printf("����ԭʼ�׽���ʧ��\n");
			return -1;
		}
		//����IP_HDRINCL ѡ�� �����Լ�����IP��
		if (setsockopt(RawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&on, sizeof(int)) < 0)  //ʧ��
		{
			printf("����IP_HDRINCLʧ�� ������%d\n", GetLastError());
			return -1;
		}

		/* ����ַ */
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
			if (err != 10060)//��ʱ���󲻷���
			{
				printf("recv data error: %d ", err);
				goto End;
				return -1;
			}
			else if (err == 0x274c)
				fprintf(stdout, "����ʱ.\n ");
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
				printf("���粻�ɴ�!\n");
				break;
			}
			case 1:
			{
				printf("�������ɴ�!\n");
				break;
			}
			case 2:
			{
				printf("Э�鲻�ɴ�!\n");
				break;
			}
			case 3:
			{
				printf("�˿ڲ��ɴ�!\n");
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

	/* ���յ���IP�ṹ + ICMP�ṹ */
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
		scanf("%s", IpAddress); //��������IP��ַ
		 
		PingIp(IpAddress);          //Ping Ĭ��4��

	}

	return 0;
}


//�������� 
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