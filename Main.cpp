/*
�쳣���༭��=���߼�=������ִ�б���=����
*/
#include <windows.h>
#include <iostream>

void _declspec(naked) ShellCode()
{
	__asm
	{
		/*
		���ַ���ת��ascii
		LoadLibraryA    4C 6F 61 64  4C 69 62 72  61 72 79 41  00
		GetProcAddress  47 65 74 50  72 6F 63 41  64 64 72 65  73 73 00
		user32.dll      75 73 65 72  33 32 2E 64  6C 6C 00
		MessageBoxA     4D 65 73 73  61 67 65 42  6F 78 41 00
		I Love You      49 20 4C 6F  76 65 20 59  6F 75 00
		*/
		pushad
		sub esp, 0x30

		// 
		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1

		push 0x756F
		push 0x59206576
		push 0x6F4C2049

		push 0x41786F
		push 0x42656761
		push 0x7373654D

		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1
		mov ax, 0x6C6C
		mov word ptr ds : [esp - 2] , ax
		sub esp, 0x2
		push 0x642E3233
		push 0x72657375

		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1
		mov ax, 0x7373
		mov word ptr ds : [esp - 2] , ax
		sub esp, 0x2
		push 0x65726464
		push 0x41636F72
		push 0x50746547

		mov byte ptr ds : [esp - 1] , 0x0
		sub esp, 0x1
		push 0x41797261
		push 0x7262694C
		push 0x64616F4C

		mov ecx, esp
		push ecx            // �ַ����׵�ַ
		call fun_Payload

		popad
		retn

		// 2. ��ȡģ���ַ
		fun_GetModule :
		push ebp
			mov ebp, esp
			sub esp, 0xC
			push esi

			mov esi, dword ptr fs : [0x30]  // PEBָ��
			mov esi, [esi + 0xC]            // LDR�������ַ
			mov esi, [esi + 0x1C]           // list
			mov esi, [esi]                  // list�ĵڶ��� kernel32
			mov esi, [esi + 0x8]            // kernel32.dll base
			mov eax, esi

			pop esi
			mov esp, ebp
			pop ebp
			retn

			/*
			��ȡ���̵�ַ
			@param dllBase   ģ���ַ
			@param funName   ������
			@param strlen    ��������
			*/
		fun_GetProcAddress:
		push ebp
			mov ebp, esp
			sub esp, 0x10
			push esi
			push edi
			push edx
			push ebx
			push ecx

			mov edx, [ebp + 0x8]   // dllBase
			mov esi, [edx + 0x3C]  // lf_anew
			lea esi, [edx + esi]   // NT header
			mov esi, [esi + 0x78]  // ������RVA
			lea esi, [edx + esi]   // ������VA

			mov edi, [esi + 0x1C]  // EAT RVA
			lea edi, [edx + edi]   // EAT VA
			mov[ebp - 0x4], edi    // EAT VA ����ֲ�������

			mov edi, [esi + 0x20]  // ENT RVA
			lea edi, [edx + edi]   // ENT VA
			mov[ebp - 0x8], edi    // ENT VA ����ֲ�������

			mov edi, [esi + 0x24]  // EOT RVA
			lea edi, [edx + edi]   // EOT VA
			mov[ebp - 0xC], edi    // EOT VA ����ֲ�������

			// �Ƚ��ַ��� ��ȡAPI
			xor eax, eax           // EAX���㣬EAX��Ϊ����
			cld
			jmp tag_cmpFirst       // ��һ��ִ��eaxֻ��Ϊ0
			tag_cmpLoop :
		inc eax
			tag_cmpFirst :
		mov esi, [ebp - 0x8]         // ȡ��ENT
			mov esi, [esi + eax * 4] // RVA
			mov edx, [ebp + 0x8]     // dllBase +++
			lea esi, [edx + esi]     // ���������ַ���

			mov edi, [ebp + 0xC]     // ȡfunName���Σ�Ҫ���ҵĺ�����
			mov ecx, [ebp + 0x10]    // ȡstrlen���Σ�ѭ������

			// ѭ��ǰ����־λҪ����
			repe cmpsb               // esiָ�������ediָ����������Ƚ�
			jne tag_cmpLoop          // ���������ѭ����ʼ��

			// �ҵ�������
			mov esi, [ebp - 0xC]     // EOT
			xor edi, edi             // Ϊ�˲�Ӱ�������edi
			mov di, [esi + eax * 2]  // �ҵ�EAT������ eot��word���ͣ����Գ���2
			mov esi, [ebp - 0x4]     // ȡ��EAT��ַ
			mov esi, [esi + edi * 4] // ������ַRVA
			mov edx, [ebp + 0x8]     // ȡ��dllBase
			lea eax, [edx + esi]     // ������ַ

			pop ecx
			pop ebx
			pop edx
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 0xC

			/*
			����һ������
			@param �ַ����׵�ַ
			*/
		fun_Payload:
		push ebp
			mov ebp, esp
			sub esp, 0x20
			push esi
			push edi
			push edx
			push ebx
			push ecx

			// 1. ���õ�dllBase
			call fun_GetModule
			mov[ebp - 0x4], eax           // dllBase�浽ebp-4��

			// 2. ��ȡLoadLibraryA
			push 0xD                      // ����3 strlen ����
			lea ecx, [ebp + 0xC]          // ��ȡ�ַ����׵�ַ
			push ecx                      // Ҫ���ҵĺ�����
			push eax                      // dllbBase
			call fun_GetProcAddress
			mov[ebp - 0x8], eax           // LoadLibrary��ַ

			// 3. ��ȡGetProcAddress
			push 0xF
			lea ecx, [ebp + 0xC + 0xD]
			push ecx
			push[ebp - 0x4]
			call fun_GetProcAddress
			mov[ebp - 0xC], eax           // ���GetProcAdress��ַ

			// 4. ����LoadLibraryA ����user32.dll
			lea ecx, [ebp + 0xC + 0xD + 0xF]          // user32.dll�ַ�����ַ
			push ecx
			call[ebp - 0x8]               // ���� LoadLibraryA ��ȡuser32.dll
			mov[ebp - 0x10], eax          // ���ؽ��(user32 base)��ŵ�ebp - 0x10

			// 5. ����GetProcaddress����ȡMessageBoxA��ַ
			mov ecx, [ebp + 0x8]
			lea ecx, [ecx + 0x27]         // MessageBoxA�ַ�����ַ
			push ecx
			push[ebp - 0x10]
			call[ebp - 0xC]               // ����GetProcAddress����
			mov[ebp - 0x14], eax          // ���ؽ��(MessageBoxA�ĵ�ַ)�ŵ�ebp - 0x14

			// 6. ��� I Love You
			push 0
			push 0
			mov ecx, [ebp + 0x8]
			lea ecx, [ecx + 0x33]
			push ecx
			push 0
			call[ebp - 0x14]

			pop ecx
			pop ebx
			pop edx
			pop edi
			pop esi
			mov esp, ebp
			pop ebp
			retn 0x4


	}
}

int main()
{
	/*_asm
	{
		call ShellCode;
	}*/
	ShellCode();
	return 0;
}