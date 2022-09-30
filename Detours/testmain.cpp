#include <iostream>
#include <Windows.h>

int main()
{
    Sleep(20000);
    HANDLE hFile = CreateFileA("test.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Open file failed" << std::endl;
        return 0;
    }
    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == -1)
    {
        std::cout << "SetFilePointer error" << std::endl;
        return 0;
    }
    char buff[20] = { 0 };
    DWORD dwWrite;
    if (!ReadFile(hFile, &buff, 5, &dwWrite, NULL))
    {
        std::cout << "WriteFile error" << std::endl;
        return 0;
    }
    std::cout << "size: " << dwWrite << std::endl;
    std::cout << "buffer: " << buff << std::endl;
    CloseHandle(hFile);
    hFile = CreateFileA("test.txt", DELETE, 0, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Open file failed" << std::endl;
    }
    CloseHandle(hFile);
	return 0;
}