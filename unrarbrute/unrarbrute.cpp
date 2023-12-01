
/*
 *  unrarbrute.exe benytter unrar.exe til å teste flere passord om gangen via brute forcing og multithreading.
 *  Støtter opptil 128 tråder hvor hver tråd blir tildelt et passord å teste fra alle mulige kombinasjoner.
 * 
 *  Antall tråder som benyttes avgjøres av std::thread::hardware_concurrency.
 *  https://learn.microsoft.com/en-us/cpp/standard-library/thread-class?view=msvc-170#hardware_concurrency
 * 
 *  Laget fordi jeg glemte passordet på ei fil på jobb...
 *
 *  (c)2023 dj <thronic@gmail.com> 
 */

#include <iostream>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <io.h>
#include <fcntl.h>
#include "misc.h"
#include "process.h"
#include "unrar.h"
#include "unrarstuff.h"

int password_size_reached = 0;
int t_running[128] = {0};
std::vector<std::wstring> thread_messages;
std::mutex mutexlock;
std::wstring password_found;
bool runprogram = true;
std::wstring TargetRarFile;
int NumThreads = 0;
std::wstring LogPass = L"";
std::wstring LogPassContinue = L"";

// Prototyper.
void hidecursor(bool hide);


void ClearConsole()
{
	COORD topleft = {0,0};
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen;
	DWORD written;

	GetConsoleScreenBufferInfo(console, &screen);
	FillConsoleOutputCharacterA(console, ' ', screen.dwSize.X * screen.dwSize.Y, topleft, &written);
	SetConsoleCursorPosition(console, topleft);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType) {
		case CTRL_C_EVENT:

			// Globalt signal om stopp.
			runprogram = false;

			// Lagre passord i tilfelle man vil fortsette.
			std::wofstream loggfil("unrarbrute_last_tried.log", std::ios::binary);
			loggfil << trypass;
			loggfil.close();

			// Vis kursør igjen.
			hidecursor(false);

			// Avslutt.
			return 1;
	}
	return 0;
}

wchar_t chars[67] = {
	'0','1','2','3','4','5','6','7','8','9',
	'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
	'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
	'.',',','-','_','@' // Tilpass brutethreadhelper loopen dersom flere tegn legges til.
};

void TestPassord(int threadnum)
{
	// Bare kjør en test på arkivet for å verifisere passord, ikke pakk ut noe.
	std::wstring cmd = L"unrar.exe t -p";
	cmd.append(trypass_registry[threadnum]);
	cmd.append(L" "+ TargetRarFile +L" 2>&1");

	/* DEBUGGING - kontroll av passordargumenter.  
	mutexlock.lock();
	std::wofstream loggfil("TestPassord1.log", std::ios::binary | std::ios::app);
	loggfil << trypass_registry[threadnum] << ", " << std::to_wstring(threadnum) << '\n';
	loggfil.close();
	mutexlock.unlock(); */

	FILE *call = _wpopen(cmd.c_str(), L"r");
	if (call == 0)
		MiscStaticFuncsClass::GetErrorW(L"Feil ved kjøring av unrar.exe.",true);

	// Les output.
	wchar_t ReadBuf[4096] = {0};
	while (fgetws(ReadBuf, 4096, call) != 0) {
		if (wcsstr(ReadBuf, L"All OK") != 0) {
			_pclose(call);
			password_found = trypass_registry[threadnum];
			runprogram = false;

			/* DEBUGGING - kontroll av argumentutvinning.
			mutexlock.lock();
			std::wcout << L"FANT PASSORDET!!!";   
			std::wofstream loggfil("TestPassord2.log", std::ios::binary | std::ios::app);
			loggfil << trypass_registry[threadnum] << ", " << std::to_wstring(threadnum) << '\n';
			loggfil.close();
			mutexlock.unlock();  */

			break;
		}
	}

	_pclose(call);
	t_running[threadnum] = 0;
}

// Benytt unrar.dll i stedet for å åpne unrar.exe prosesser, burde være kjappere.
void TestPassordViaDLL(int threadnum)
{
	if (TestRarPass(TargetRarFile.c_str(), threadnum)) {
		password_found = trypass_registry[threadnum];
		runprogram = false;
		hidecursor(false);
	}

	t_running[threadnum] = 0;
}

// Trådhjelper for rekursiv graving ned i passordlengder.
int AttemptsNumForLog = 0;
void brutethreadhelper(int posisjon, int password_size)
{
	for (int a=0; a<67; a++) {

		// Avbryt hvis en tråd har funnet passordet.
		if (!runprogram)
			return;

		// Samle opp passordkombinasjoner.
		trypass[posisjon] = chars[a];
		
		// Rekursivt kall avhengig av passordlengde for å begynne bakfra.
		if (password_size > (posisjon+1)) {
			brutethreadhelper(posisjon+1, password_size);
			continue;
		}

		// Hopp over test hvis det skal fortsettes fra en forrige gang,
		// inntil algoritmen kommer frem til fortsettelsen i loggfilen. 
		if (LogPass != L"" && memcmp(trypass, LogPass.c_str(), LogPass.length()*sizeof(wchar_t)) != 0) {
			continue;
		} else if (LogPass != L"") {
			LogPassContinue = LogPass;
			LogPass = L"";
		}

		AttemptsNumForLog++;
		if (AttemptsNumForLog >= 1000) {
			// Lagre passord i tilfelle man vil fortsette og programmet ble uventet drept på noe vis.
			std::wofstream loggfil("unrarbrute_last_tried.log", std::ios::binary);
			loggfil << trypass;
			loggfil.close();
			AttemptsNumForLog = 0;
		}

		// Test passord, finn en ledig tråd.
		bool FoundAvailThread = false;
		while (!FoundAvailThread) {
			for (int b=0; b<NumThreads; b++) {
				if (t_running[b] == 0) {

					FoundAvailThread = true;
					t_running[b] = 1;
					thread_messages.at(b) = trypass;
					memcpy(trypass_registry[b], trypass, 1024*sizeof(wchar_t));
					std::thread _t (TestPassordViaDLL, b);
					_t.detach();

					/* DEBUGGING av kombinasjons-algoritme. At alle kombinasjoner blir forsøkt.	   
					std::wofstream loggfil("brutethreadhelper.log", std::ios::binary | std::ios::app);
					loggfil << trypass_registry[b] << ", " << std::to_wstring(b) << '\n';
					loggfil.close(); */

					break;
				}
			}
		}
	}
}

void brutethread()
{
	while(runprogram) {

		// Forsøk en kombinasjonslengde om gangen, fordelt over flere tråder.
		password_size_reached += 1;

		// Kjør kombinasjoner for lengden.
		for (int a=0; a<password_size_reached; a++) {
			if (password_found == L"")
				brutethreadhelper(a, password_size_reached);
			else
				break;
		}
	}
}

int wmain(int argc, wchar_t* argv[])
{
	SetConsoleCtrlHandler(CtrlHandler, true);
	_setmode(_fileno(stdout), _O_U8TEXT);
	ClearConsole();
	
	if (argc == 1) {
		std::wcout << "Bruk: unrarbrute.exe file.rar\n";
		hidecursor(false);
		return 0;
	} else if (!MiscStaticFuncsClass::FileExistsW(argv[1])) {
		std::wcout << "Filen " << argv[1] << " må eksistere i samme mappe.\n";
		hidecursor(false);
		return 0;
	} else if (!MiscStaticFuncsClass::FileExistsW(L"UnRAR64.dll")) {
		std::wcout << "UnRAR64.dll må eksistere i samme mappe.\n";
		hidecursor(false);
		return 0;
	}

	// Sjekk etter loggfil, for å kunne fortsette fra før.
	if (MiscStaticFuncsClass::FileExistsW(L"unrarbrute_last_tried.log")) {
		std::wifstream loggfil("unrarbrute_last_tried.log", std::ios::binary);
		loggfil >> LogPass;
		loggfil.close();
	}

	// Registrer målfil globalt.
	TargetRarFile = argv[1];
 
	// Finn ut antall tråder tilgjengelig.
	NumThreads = std::thread::hardware_concurrency();
	if (NumThreads == 0)
		NumThreads = 1;
	for (int a=0; a<NumThreads; a++)
		thread_messages.push_back(L"Laster startpunkt...");

	// Toppmelding i program.
	std::wcout << "unrarbrute.exe, av Dag J Nedrelid <dj@thronic.com> 2023.\n" <<
		"Starttid: " << MiscStaticFuncsClass::DatotidFullW() << "\n" << 
		"Utfører multitrådsangrep på [ " << TargetRarFile << " ]\n"
		"Kombinerer alfanumeriske tegn (a-z,A-Z,0-9) og .,-_@\n\n";
	
	// Start forsøkstråd.
	hidecursor(true);
	std::thread _t (brutethread);
	_t.detach();

	// Overvåk forsøk.
	//std::remove("brutethreadhelper.log"); // DEBUGGING.
	//std::remove("TestPassord1.log"); // DEBUGGING.
	//std::remove("TestPassord2.log"); // DEBUGGING.

	while(runprogram) {

		if (password_found != L"")
			break;

		// Gi tråder tid å rapportere.
		Sleep(100);

		// Rapporter meldinger fra tråder.
		COORD msgpos = {0,5};
		HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
		for (int a=0; a<thread_messages.size(); a++) {
			SetConsoleCursorPosition(console, msgpos);
			std::wcout << L"Tråd " << std::to_wstring(a+1) << ": " << thread_messages.at(a) << "                         ";
			msgpos.Y += 1;
		}

		// Vis evt. fortsettelse fra tidligere søk.
		if (LogPassContinue != L"") {
			msgpos.Y += 1;
			SetConsoleCursorPosition(console, msgpos);
			std::wcout << L"Fortsetter søk fra loggfil: " << LogPassContinue;
		}
	}

	if (password_found != L"") 
		std::wcout << L"\n\nFant passord: " << password_found << "\n\n";

	if (!runprogram && password_found == L"")
		std::wcout << L"\n\nFanget opp CTRL+C eller avbrutt før funn, lagrer siste forsøkte passord ("<< trypass <<L") og avslutter...\n";

	return 0;
}
