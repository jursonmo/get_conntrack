#include <stdio.h>  
#include <fcntl.h>  
#include <sys/mman.h>  
#include <stdlib.h>  
#include <string.h>  
#include <linux/ioctl.h>
#include <sys/un.h>  
#include <sys/socket.h>  
#include <stddef.h> 
#include <errno.h>

#include "ct_info.h"

#include "ntrack_rbf.h"


#define KUMAP_IOC_MAGIC	'K'
#define KUMAP_IOC_SEM_WAIT _IOW(KUMAP_IOC_MAGIC, 1, int)
#define unix_path "/root/unixSocket"
int my_write(int fd,void *buffer,int length);
int unix_socket_listen(const char *servername) ;

int main( void )  
{  
    int fd, unix_fd,com_fd, un_addr_len, size;  
    char *buffer;  
	char *mapBuf;
   int cmd, arg; 
	rbf_t *rbf;
	char *data = NULL;
	struct dnat_info di;
	struct sockaddr_un cli_addr;
	int di_len = sizeof(struct dnat_info);
	
    fd = open("/dev/kumap/kudev", O_RDWR);//打开设备文件，内核就能获取设备文件的索引节点，填充inode结构  
    if(fd<0)  
    {  
        printf("open device is error,fd = %d\n",fd);  
        return -1;  
    }  
    /*测试一：查看内存映射段*/  
    printf("before mmap\n");  
    //sleep(15);//睡眠15秒，查看映射前的内存图cat /proc/pid/maps  
    buffer = (char *)malloc(1024);  
    memset(buffer, 0, 1024);  
    mapBuf = mmap(NULL, 1024, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);//内存映射，会调用驱动的mmap函数  
    printf("after mmap\n");  
    //sleep(15);//睡眠15秒，查看映射前的内存图cat /proc/pid/maps  
	/*	
    strncpy(buffer, mapBuf, 10);//从映射段读取数据  
    printf("get mapbuf ->buf = %s\n", buffer);//如果读取出来的数据和写入的数据一致，说明映射段的确成功了  

    strcpy(mapBuf, "Driver Test");//向映射段写数据  
    memset(buffer, 0, 1024);  
    strcpy(buffer, mapBuf);//从映射段读取数据  
    printf("buf = %s\n", buffer);//如果读取出来的数据和写入的数据一致，说明映射段的确成功了  
	*/
	
  	printf(" di_len =%d \n", di_len);
    cmd =KUMAP_IOC_SEM_WAIT;   
	
     rbf = (rbf_t *)mapBuf;
     if (rbf->magic != 12345) {
	printf("rbf->magic =%d\n", rbf->magic);
	return -1;
     }
	printf("unix_socket_listenning \n"); 

	unix_fd = unix_socket_listen(unix_path);
	if(unix_fd<0)  
 	 {  
     		printf("Error[%d] when listening...\n", errno); 
		perror("unix_socket_create error:");
     		return 0;  
 	 } 
	un_addr_len = sizeof(cli_addr);
	com_fd=accept(unix_fd,(struct sockaddr*)&cli_addr,&un_addr_len);  
	if(com_fd<0)  
	{  
		perror("cannot accept client connect request");  
		close(unix_fd);  
		unlink(unix_path);  
		return -1;  
	}  	
  while (1){
  	  printf("ioctl  ing \n");
	    if (ioctl(fd, cmd, &arg)< 0) {
		printf("ioctl fail\n");
		return -1;
	    }
	printf("ioctl success\n");
	
	 while (1){
		data = NULL;
		printf("rbf_get_data starting \n");
		//sleep(1);
		data = rbf_get_data(rbf);
		if (!data) {
			printf("rbf_get_data fail\n");
			break;
		}
		printf("rbf_get_data end \n");
		memcpy(&di, data, di_len);
		rbf_release_data(rbf);
		 size = my_write(com_fd, &di, di_len);
		 if(size !=di_len)  {
			printf("send  size=%d \n", size);
			goto out;
		 }
		dump_dnat_info(&di);
	 }		
  }

 out: 
  close(unix_fd); 
   unlink(unix_path);

     munmap(mapBuf, 1024);//去除映射  
    free(buffer);  
    close(fd);//关闭文件，最终调用驱动的close  
    return 0;  
}

int my_write(int fd,void *buffer,int length)
{
	int bytes_left;
	int written_bytes;
	char *ptr;

	ptr=buffer;
	bytes_left=length;
	while(bytes_left>0)
	{
	        
	         written_bytes=write(fd,ptr,bytes_left);
	         if(written_bytes<=0)
	         {       
	                 if(errno==EINTR)
	                         written_bytes=0;
	                 else             
	                         return(-1);
	         }
	         bytes_left-=written_bytes;
	         ptr+=written_bytes;     
	}
	return length - bytes_left;
}

int unix_socket_listen(const char *servername)  
{   
  int fd;  
  struct sockaddr_un un;   
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)  
  {  
     return(-1);   
  }  
  int len, rval;   
  unlink(servername);               /* in case it already exists */   
  memset(&un, 0, sizeof(un));   
  un.sun_family = AF_UNIX;   
  strcpy(un.sun_path, servername);   
  len = offsetof(struct sockaddr_un, sun_path) + strlen(servername);   
  /* bind the name to the descriptor */   
  if (bind(fd, (struct sockaddr *)&un, len) < 0)  
  {   
    rval = -2;   
  }   
  else  
  {  
      if (listen(fd, 5) < 0)      
      {   
        rval =  -3;   
      }  
      else  
      {  
        return fd;  
      }  
  }  
  int err;  
  err = errno;  
  close(fd);   
  errno = err;  
  return rval;    
}

