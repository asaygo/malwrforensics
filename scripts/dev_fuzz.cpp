#include <stdio.h>
#include <windows.h>
#include <shellapi.h>

#define BUF_MAX_SIZE 1024

#define DEV_NAME L"\\\\.\\<insert_name>"

// return 0 if it's not null
int is_null(unsigned char buf[], int size)
{
  for (int i=0; i<size; i++)
  {
    if (buf[i] != 0)
      return 0;
  }
  return 1;
}

int fuzz_deviceW(LPWSTR device)
{
  HANDLE h_device;
  unsigned char buf_in[BUF_MAX_SIZE];
  unsigned char buf_out[BUF_MAX_SIZE];
  DWORD bytes;

  ZeroMemory(buf_in, BUF_MAX_SIZE);
  ZeroMemory(buf_out, BUF_MAX_SIZE);

  h_device = CreateFileW(device, NULL, FILE_SHARE_READ|FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, 0, NULL);

  if (h_device == INVALID_HANDLE_VALUE) {
    perror("Can't find the device\n");
    printf("LastError: %d\n", GetLastError());
    return 0;
  }
  else
    printf("Device exists\n");

  for (int ioctlcode = 0x0; ioctlcode < 0x1000; ioctlcode++)
  {
    printf("Test IOCTLCODE: %08x\n", ioctlcode);
    for (int i=8; i<BUF_MAX_SIZE; i++)
    {
      // Init buffer with junk data
      for (int j=0; j<i; j++) 
        buf_in[j] = 0x41;

      // Send junk data to device
      DeviceIoControl(h_device, ioctlcode, &buf_in, i, &buf_out, i, &bytes, NULL);

      // Check if we got anything back
      if (bytes > 0 && bytes < BUF_MAX_SIZE)
      {
        // Show how many bytes we've got
        printf("\tSize %d returned %d bytes\n", i, bytes);

        // Is the buffer NULL ?
        if (is_null(buf_out, bytes) == 0) {

          printf("\tBuffer is not NULL!\n");

          // Show the bytes received
          for(int ndx=0; ndx<(int)bytes; ndx++) {
            printf("%02x ", buf_out[ndx]);
            if (ndx%8) printf("\n");
          }
        }
      }// if bytes
    }// for buf size
  }// for ioctlcode

  CloseHandle(h_device);
  return 1;

}

int main()
{
  fuzz_deviceW(DEV_NAME);
  return 1;
}
