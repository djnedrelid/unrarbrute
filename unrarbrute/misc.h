﻿#include <Shlwapi.h>	// Sti informasjon etc.

//
// Multiverktøy-klasse for diverse nyttige statiske funksjoner.
//

class MiscStaticFuncsClass
{
	private:
	public:
	//
	// Returnerer f.eks. Sun 10:59:59
	//
	static std::wstring DatotidW()
	{
		time_t now = time(0);
		tm tid;
		localtime_s(&tid, &now);
		std::wstring datotid;

		//(dato, lar stå for referanse).
		//datotid.append( std::to_wstring(tid.tm_year+1900) + L"." );
		//datotid.append( ((tid.tm_mon+1) < 10 ? L"0" + std::to_wstring(tid.tm_mon+1) : std::to_wstring(tid.tm_mon+1) ) + L".");
		//datotid.append( ((tid.tm_mday) < 10 ? L"0" + std::to_wstring(tid.tm_mday) : std::to_wstring(tid.tm_mday) ) + L" ");
	
		// Vis kun dagsnavn i stedet for å spare plass.
		std::vector<std::wstring> dager = { L"Sun",L"Mon",L"Tue",L"Wed",L"Thu",L"Fri",L"Sat" };
		for (unsigned int n=0; n<dager.size(); n++)
			if (n == tid.tm_wday)
				datotid.append( dager[n] + L" ");

		// Tid.
		datotid.append( ((tid.tm_hour) < 10 ? L"0" + std::to_wstring(tid.tm_hour) : std::to_wstring(tid.tm_hour) ) + L":");
		datotid.append( ((tid.tm_min) < 10 ? L"0" + std::to_wstring(tid.tm_min) : std::to_wstring(tid.tm_min) ) + L":");
		datotid.append( ((tid.tm_sec) < 10 ? L"0" + std::to_wstring(tid.tm_sec) : std::to_wstring(tid.tm_sec) ));

		return datotid;
	}

	//
	// Returnerer f.eks. 2021-12-01 17:38:00
	//
	static std::wstring DatotidFullW()
	{
		time_t now = time(0);
		tm tid;
		localtime_s(&tid, &now);
		std::wstring datotid;

		// Dato.
		datotid.append( std::to_wstring(tid.tm_year+1900) + L"." );
		datotid.append( ((tid.tm_mon+1) < 10 ? L"0" + std::to_wstring(tid.tm_mon+1) : std::to_wstring(tid.tm_mon+1) ) + L".");
		datotid.append( ((tid.tm_mday) < 10 ? L"0" + std::to_wstring(tid.tm_mday) : std::to_wstring(tid.tm_mday) ) + L" ");
	
		// Vis kun dagsnavn i stedet for å spare plass.
		std::vector<std::wstring> dager = { L"Sun",L"Mon",L"Tue",L"Wed",L"Thu",L"Fri",L"Sat" };
		for (unsigned int n=0; n<dager.size(); n++)
			if (n == tid.tm_wday)
				datotid.append( dager[n] + L" ");

		// Tid.
		datotid.append( ((tid.tm_hour) < 10 ? L"0" + std::to_wstring(tid.tm_hour) : std::to_wstring(tid.tm_hour) ) + L":");
		datotid.append( ((tid.tm_min) < 10 ? L"0" + std::to_wstring(tid.tm_min) : std::to_wstring(tid.tm_min) ) + L":");
		datotid.append( ((tid.tm_sec) < 10 ? L"0" + std::to_wstring(tid.tm_sec) : std::to_wstring(tid.tm_sec) ));

		return datotid;
	}

	//
	// Returnerer f.eks. Sun 10:59:59
	//
	static std::string DatotidA()
	{
		time_t now = time(0);
		tm tid;
		localtime_s(&tid, &now);
		std::string datotid;
	
		// Vis kun dagsnavn i stedet for å spare plass.
		std::vector<std::string> dager = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
		for (unsigned int n=0; n<dager.size(); n++)
			if (n == tid.tm_wday)
				datotid.append( dager[n] + " ");

		// Tid.
		datotid.append( ((tid.tm_hour) < 10 ? "0" + std::to_string(tid.tm_hour) : std::to_string(tid.tm_hour) ) + ":");
		datotid.append( ((tid.tm_min) < 10 ? "0" + std::to_string(tid.tm_min) : std::to_string(tid.tm_min) ) + ":");
		datotid.append( ((tid.tm_sec) < 10 ? "0" + std::to_string(tid.tm_sec) : std::to_string(tid.tm_sec) ));

		return datotid;
	}

	//
	// Returnerer true hvis fil eksisterer, false hvis ikke.
	//
	static bool FileExistsW(const wchar_t* f) 
	{
		// Er det en enkeltfil?
		if (PathIsDirectoryW(f) == 0) {
		
			// Sjekk om filen faktisk eksisterer.
			std::wifstream filtest(f);

			if (!filtest.good()) {
				return false;
			} else {
				filtest.close();
				return true;
			}
		} else {
			return false;
		}
	}

	//
	// Returnerer true hvis fil eksisterer, false hvis ikke.
	//
	static bool FileExistsA(const char* f) 
	{
		// Er det en enkeltfil?
		if (PathIsDirectoryA(f) == 0) {
		
			// Sjekk om filen faktisk eksisterer.
			std::ifstream filtest(f);

			if (!filtest.good()) {
				return false;
			} else {
				filtest.close();
				return true;
			}
		} else {
			return false;
		}
	}

	//
	// Returnerer antall bytes som ble funnet i filen.
	//
	static unsigned long long FileSizeInBytesW(const wchar_t* filename)
	{
		unsigned long long filesize = 0;
		std::wifstream fil;
		fil.open(filename, std::ios::binary);
		fil.seekg(0, std::ios::end);
		filesize = (unsigned long long)fil.tellg();
		fil.close();

		return filesize;
	}

	//
	// Returnerer antall bytes som ble funnet i filen.
	//
	static unsigned int FileSizeInBytesA(const char* filename)
	{
		int filesize = 0;
		std::ifstream fil;
		fil.open(filename, std::ios::binary);
		fil.seekg(0, std::ios::end);
		filesize = (int)fil.tellg();
		fil.close();

		return filesize;
	}

	//
	// Åpner meldingsboks med kun beskjed, for generell informasjon.
	//
	static void BeskjedW(const wchar_t* s)
	{
		MessageBoxW(0, s, L"Message", MB_OK | MB_ICONINFORMATION);
	}

	//
	// Åpner meldingsboks med kun beskjed, for generell informasjon.
	//
	static void BeskjedA(const char* s)
	{
		MessageBoxA(0, s, "Message", MB_OK | MB_ICONINFORMATION);
	}

	//
	// lpszFunction = Manuell feilbeskjed.
	// HandleExit = Exit(EXIT_FAILURE).
	//
	static void GetErrorW(std::wstring lpszFunction, bool HandleExit)
	{
		unsigned long err = GetLastError();
		std::wstring lpDisplayBuf;
		wchar_t* lpMsgBuf;

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			err,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR)&lpMsgBuf,
			0,
			NULL
		);

		lpDisplayBuf.append(lpszFunction + L"\n\n");
		lpDisplayBuf.append(L"Details: (" + std::to_wstring(err) + L") ");
		lpDisplayBuf.append(lpMsgBuf);

		std::wofstream loggfil("feilmeldinger.log", std::ios::binary | std::ios::app);
        loggfil << lpDisplayBuf.c_str() << '\n';
        loggfil.close();

		MessageBoxW(
			NULL,
			(LPCWSTR)lpDisplayBuf.c_str(),
			L"Critical Message",
			MB_OK | MB_ICONINFORMATION
		);

		if (HandleExit) {
			// EXIT_FAILURE = 1. 
			// EXIT_SUCCESS = 0.
			exit(EXIT_FAILURE);
		}
	}

	//
	// lpszFunction = Manuell feilbeskjed.
	// HandleExit = Exit(EXIT_FAILURE).
	//
	static void GetErrorA(std::string lpszFunction, bool HandleExit)
	{
		unsigned long err = GetLastError();
		std::string lpDisplayBuf;
		char* lpMsgBuf;

		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			err,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&lpMsgBuf,
			0,
			NULL
		);

		lpDisplayBuf.append(lpszFunction + "\n\n");
		lpDisplayBuf.append("Details: (" + std::to_string(err) + ") ");
		lpDisplayBuf.append(lpMsgBuf);

		MessageBoxA(
			NULL,
			(LPCSTR)lpDisplayBuf.c_str(),
			"Critical Message",
			MB_OK | MB_ICONINFORMATION
		);

		if (HandleExit) {
			// EXIT_FAILURE = 1. 
			// EXIT_SUCCESS = 0.
			exit(EXIT_FAILURE);
		}
	}
};

//
//	Div funksjoner.
//
void hidecursor(bool hide)
{
	CONSOLE_CURSOR_INFO info;

	if (hide) 
		info.bVisible = 0;
	else
		info.bVisible = 1;

	info.dwSize = 100;
	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleCursorInfo(consoleHandle, &info);
}