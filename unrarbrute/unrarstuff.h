#pragma once

enum { EXTRACT, TEST, PRINT, LIST };
enum ERR_TYPE {ERR_OPEN, ERR_READ, ERR_PROCESS};

wchar_t trypass[1024] = {0};
wchar_t trypass_registry[128][1024] = {0};

int CALLBACK CallbackProc(UINT msg,LPARAM UserData,LPARAM P1,LPARAM P2)
{
  switch(msg)
  {
    case UCM_NEEDPASSWORDW:
      {
		//wprintf(L"\nPassword required: ");
   
        // fgetws may fail to read non-English characters from stdin
        // in some compilers. In this case use something more appropriate
        // for Unicode input.

		// Fikser passord her siden docs sier at det støtter krypterte headere, som RARSetPassword ikke ser ut til å gjøre.
		// https://python-unrar.readthedocs.io/en/latest/_downloads/unrar_manual.txt
		memcpy((wchar_t*)P1, (const void*)trypass_registry[(int)UserData], wcslen(trypass_registry[(int)UserData])*sizeof(wchar_t));
      }
      return(1);

	case UCM_PROCESSDATA:
      return(-1); // Ikke gjør noe med utpakket data, skal kun teste passord.
  }

  return(0);
}

void OutError(unsigned int Error, int ErrType)
{
  switch(Error)
  {
    case ERAR_NO_MEMORY:
      MiscStaticFuncsClass::GetErrorW(L"Not enough memory.", true);
      break;
    case ERAR_BAD_DATA:
	  MiscStaticFuncsClass::GetErrorW(L"The archive header or data are damaged", true);
      break;
    case ERAR_BAD_ARCHIVE:
	  MiscStaticFuncsClass::GetErrorW(L"The file is not a RAR archive", true);
      break;
    case ERAR_UNKNOWN_FORMAT:
	  MiscStaticFuncsClass::GetErrorW(L"Unknown archive format", true);
      break;
    case ERAR_EOPEN:
      if (ErrType==ERR_PROCESS) { // Returned by RARProcessFile.
		MiscStaticFuncsClass::GetErrorW(L"Volume open error", true);
      } else {
		MiscStaticFuncsClass::GetErrorW(L"Cannot open the RAR file.", true);
	  }
      break;
    case ERAR_ECREATE:
	  MiscStaticFuncsClass::GetErrorW(L"File create error", true);
      break;
    case ERAR_ECLOSE:
	  MiscStaticFuncsClass::GetErrorW(L"File close error", true);
      break;
    case ERAR_EREAD:
	  MiscStaticFuncsClass::GetErrorW(L"Read error", true);
      break;
    case ERAR_EWRITE:
	  MiscStaticFuncsClass::GetErrorW(L"Write error", true);
      break;
    case ERAR_SMALL_BUF:
	  MiscStaticFuncsClass::GetErrorW(L"Buffer for archive comment is too small, comment truncated", true);
      break;
    case ERAR_UNKNOWN:
	  MiscStaticFuncsClass::GetErrorW(L"Unknown error", true);
      break;
    case ERAR_MISSING_PASSWORD:
	  MiscStaticFuncsClass::GetErrorW(L"Password for encrypted file or header is not specified", true);
      break;
    case ERAR_EREFERENCE:
	  MiscStaticFuncsClass::GetErrorW(L"Cannot open file source for reference record", true);
      break;
    case ERAR_BAD_PASSWORD:
	  MiscStaticFuncsClass::GetErrorW(L"Wrong password is specified", true);
      break;
  }
}

bool OpenWasEncrypted = false;
bool TestRarPass(const wchar_t *ArcName, int tnum)
{
  HANDLE hArcData;
  int RHCode,PFCode;
  char emptypass[] = "\0";
  struct RARHeaderDataEx HeaderData;
  struct RAROpenArchiveDataEx OpenArchiveData;

  memset(&HeaderData,0,sizeof(HeaderData));
  memset(&OpenArchiveData,0,sizeof(OpenArchiveData));

  OpenArchiveData.ArcNameW=(wchar_t*)ArcName;
  OpenArchiveData.CmtBufW=NULL;
  OpenArchiveData.OpenMode=RAR_OM_EXTRACT;
  OpenArchiveData.Callback=CallbackProc;
  OpenArchiveData.UserData=tnum;
  hArcData=RAROpenArchiveEx(&OpenArchiveData);

  if (OpenArchiveData.OpenResult != 0 && OpenArchiveData.OpenResult != ERAR_BAD_PASSWORD) {
    OutError(OpenArchiveData.OpenResult, ERR_OPEN);
  } else if (OpenArchiveData.OpenResult == ERAR_BAD_PASSWORD) {
	//
	//	RAR filer med krypterte filnavn vil stange her i selve åpningen av fil.
	//	OpenWasEncrypted blir da registrert slik at jeg vet lenger nede at det er tilfellet.
	//
	OpenWasEncrypted = true;
	return false;
  }
  
  //
  //	RAR filer uten krypterte filnavn vil gå rett her og sjekkes mot interne filer.
  //
  //std::wcout << L" RARProcessFileW [" << std::to_wstring(tnum) << L"] ";
  while ((RHCode = RARReadHeaderEx(hArcData, &HeaderData)) == 0) {

		//
		// Er den interne filen i arkivet kryptert/passordbeskyttet i det hele tatt? 
		//
		if ((HeaderData.Flags & 0x04) == 0) {
			std::wstring ws = L"Filen ";
			ws.append(HeaderData.FileNameW);
			ws.append(L" er ikke kryptert...");
			hidecursor(false);
			MiscStaticFuncsClass::GetErrorW(ws.c_str(), true);
		}
		
		// Ellers gå i gang med sjekking av passord på intern arkivfil.
		PFCode = RARProcessFileW(hArcData, RAR_TEST, NULL, NULL);

		//
		// Test av arkiv OK med angitt passord.
		// OpenWasEncrypted blir satt ovenfor hvis filnavn også var kryptert og hindret åpning.
		// Hvis jeg ikke sjekker mot dette får jeg ERAR_UNKNOWN feil nedenfor, så jeg må bare 
		// anta at hvis jeg klarte å låse opp selve arkivet, trenger jeg ikke teste filer inni.
		// Arkiv som ikke har krypterte filnavn ser etter testing ut til å kunne sjekkes nedenfor OK.
		//
		if (PFCode == 0 || OpenWasEncrypted) { 
			RARCloseArchive(hArcData);
			return true;

		} else if (PFCode == ERAR_BAD_PASSWORD) {
			RARCloseArchive(hArcData);
			return false;

		} else {
			RARCloseArchive(hArcData);
			std::wstring debugtxt = L"Feil ved sjekk mot intern arkivfil: ";
			debugtxt.append(std::to_wstring(PFCode));
			MiscStaticFuncsClass::GetErrorW(debugtxt, true);
		}
  }

  RARCloseArchive(hArcData);
  return false;
}