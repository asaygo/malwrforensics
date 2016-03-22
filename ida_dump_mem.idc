auto eax;
auto start;
auto end;
auto f;

f = fopen("dump.bin", "w");

start = 0x400000;
end = 0x500000;

eax = start;
while ( eax < end )
{
   writelong(f, Dword(eax) ,0);
   eax = eax + 4;
}
fclose(f);
