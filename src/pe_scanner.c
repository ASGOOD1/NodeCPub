/* PE Scanner 
    Implementarea pentru scanarea folosing PE Heuristic
    Acest fisier contine functia pe_scan_file care primeste ca parametru calea catre un fisier executabil in format PE 
    si scaneaza acest fisier pentru a detecta posibile semne de comportament malitios, 
    cum ar fi importuri suspecte, 
    sectiuni cu permisiuni neobisnuite sau alte caracteristici care ar putea indica faptul ca fisierul este un malware 


    Datele din acest fisier(functii si constante sunt generate partial de AI, cu ajutor din partea stackoverflow si contributii proprii)

*/


#include "headers/pe_scanner.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(__linux__)
    #include <sys/mman.h>
#elif defined(__APPLE__)
    #include <sys/mman.h> // Folosit pentru a mapa fisierele in memorie
    #include <sys/types.h> // Pentru a folosi tipurile de date necesare pentru mmap si structuri de fisiere (necesar pe macOS)
#endif
#include <stdlib.h>


// Structuri si constante necesare (si pt magic numbers)
#define DOS_Header_PAD 58
#define PE_SectionHeader_PAD 12
#define PE_SectionHeader_Name 8
#define PE_24_BUFFER_SIZE 24 
#define PE_10_BUFFER_SIZE 10
#define PE_16_BUFFER_SIZE 16
#define PE_20_BUFFER_SIZE 20
#define PE0xFBUFFER_SIZE 0xF

#define PE_52_BUFFER_SIZE 52
#define PE_1023_BUFFER_SIZE 1023
#define PE_1023_BUFFER_SIZEULL 1023ULL
#define PE0x7FFULL 0x7FFULL
#define PE_256_BUFFER_SIZE 256

// Structura de mai jos tine minte informatiile din DOS Header
// Specific windows, folosit pentru a verifica daca un fisier este in format PE, deoarece toate fisierele PE valide trebuie sa inceapa cu un header DOS care contine semnatura "MZ" (0x4D 0x5A) 
//si un offset catre headerul PE, care contine informatii despre structura fisierului si sectiunile acestuia
typedef struct {
    uint8_t  e_magic[2];
    uint8_t  _pad[DOS_Header_PAD];
    uint32_t e_lfanew;
} DOS_Header;


// Structurile de mai jos tin minte informatiile din PE Header, Optional Header si Section Header
// Aceste structuri sunt folosite pentru a analiza structura fisierului PE
typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PE_FileHeader;


// Structura pentru Optional Header este impartita in doua parti: o parte comuna care contine campuri comune pentru ambele formate PE32 si PE32+, 
//si o parte specifica pentru fiecare format care contine campuri suplimentare necesare pentru a gestiona diferentele dintre cele doua formate
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
} PE_OptionalHeader_Common;

// Partea specifica pentru PE32, care include campul BaseOfData, necesar pentru a gestiona structura specifica a formatului PE32
typedef struct {
    uint8_t  Name[PE_SectionHeader_Name];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint8_t  _pad[PE_SectionHeader_PAD];
    uint32_t Characteristics;
} PE_SectionHeader;


// Structura pentru Import Descriptor, care contine informatii despre importurile din fisierul PE, cum ar fi adresele si numele functiilor importate, necesare pentru a analiza comportamentul fisierului si a detecta posibile semne de comportament malitios
typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} PE_ImportDescriptor;

#define PE_SCN_MEM_EXECUTE 0x20000000
#define PE_SCN_MEM_WRITE   0x80000000

#define PT_LOAD    1
#define PF_X       0x1
#define PF_W       0x2
#define SHT_DYNSYM 11


// Simboluri considerate suspecte

static const char *PE_INJECT[] = {
    "VirtualAlloc","VirtualAllocEx","VirtualProtect",
    "WriteProcessMemory","CreateRemoteThread","CreateRemoteThreadEx",
    "NtCreateThreadEx","RtlCreateUserThread",
    "OpenProcess","SetWindowsHookEx",
    "QueueUserAPC","NtUnmapViewOfSection",
    NULL
};
static const char *PE_ANTIDEBUG[] = {
    "IsDebuggerPresent","CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess","GetTickCount",
    "OutputDebugString","FindWindow",
    NULL
};
static const char *PE_NETWORK[] = {
    "WSAStartup","connect","send","recv",
    "InternetOpen","InternetConnect","HttpSendRequest",
    "URLDownloadToFile","WinHttpOpen",
    NULL
};


// Macro pentru a verifica daca un pointer si o dimensiune se incadreaza in limitele unui buffer dat(buffer overflow fallback)
#define BOUNDS(ptr, sz, base, fsz) \
    ((uint8_t*)(ptr) >= (uint8_t*)(base) && \
     (uint8_t*)(ptr) + (sz) <= (uint8_t*)(base) + (fsz))

// Wrapper peste write(evit sa fac verificarea de fiecare data cand dau write)
static void pe_write(int fd, const char *msg, int len) {
    if (write(fd, msg, len) < 0) {
        perror("write");
    }
}
// Transformare uint64_t in hex sau uint64_t in decimal, pentru a putea afisa informatiile intr-un format usor de citit pentru utilizator
static void s_uint(uint64_t v, int dst) {
    char buf[PE_24_BUFFER_SIZE]; int n=0;
    if (!v) { buf[n++]='0'; }
    else {
        char tmp[PE_24_BUFFER_SIZE]; int tlen=0;
        while (v) { tmp[tlen++]=(char)('0'+(v%PE_10_BUFFER_SIZE)); v/=PE_10_BUFFER_SIZE; }
        for (int i=tlen-1;i>=0;i--) buf[n++]=tmp[i];
        buf[n]='\0';
    }

    pe_write(dst, buf, n);
}
// Formatare manuala in hex
static void s_hex(uint64_t v, int dst) {
    char buf[PE_16_BUFFER_SIZE+2]; int n=2;
    buf[0]='0'; buf[1]='x';
    char hex[PE_16_BUFFER_SIZE]; int hlen=0;
    if (!v) { hex[hlen++]='0'; }
    else {
        uint64_t t=v;
        while(t){hex[hlen++]="0123456789ABCDEF"[t&PE0xFBUFFER_SIZE];t>>=4;}
        for(int i=0,j=hlen-1;i<j;i++,j--){char c=hex[i];hex[i]=hex[j];hex[j]=c;}
        
    }
    for(int i=0;i<hlen;i++) buf[n++]=hex[i];

    pe_write(dst, buf, n);
}

// Functie pentru a verifica daca un nume de functie se afla intr-o lista data de simboluri suspecte
static int in_list(const char *name, const char **list) {
    for (int i=0; list[i]; i++)
        if (strcmp(name, list[i])==0) return 1;
    return 0;
}
#define PE_LOG_M_CONST1 1.4426950
#define PE_LOG_M_CONST2 0.7213475
#define PE_LOG_M_CONST3 0.4808983
// Functie pt calculul logaritmului(Entropia Shannon) folosind o aproximare rapida, pentru a putea calcula entropia sectiunilor din fisierul PE
// si a detecta posibile semne de comportament malitios, cum ar fi sectiuni cu entropie neobisnuit de mare care ar putea indica prezenta unui packer sau a unui criptor
static double log2_approx(double x) {
    union { double d; uint64_t u; } v;
    v.d = x;
    int exp = (int)((v.u >> PE_52_BUFFER_SIZE) & PE0x7FFULL) - PE_1023_BUFFER_SIZE;
    v.u = (v.u & ~(PE0x7FFULL << PE_52_BUFFER_SIZE)) | (PE_1023_BUFFER_SIZEULL << PE_52_BUFFER_SIZE);
    double m = v.d - 1.0;
    double log2_m = m * (PE_LOG_M_CONST1 - m * (PE_LOG_M_CONST2 - m * PE_LOG_M_CONST3));
    return (double)exp + log2_m;
}
#define PE_FREQ_SIZE 256
static double shannon(const uint8_t *data, size_t len) {
    unsigned long long freq[PE_FREQ_SIZE] = {0};
    for (size_t i=0; i<len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i=0; i<PE_FREQ_SIZE; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        e -= p * log2_approx(p);
    }
    return e;
}


// Functie pentru a converti un adresa virtuala (RVA) intr-un offset in fisier, folosind informatiile din sectiunile fisierului PE, 
//necesara pentru a accesa corect datele din fisierul PE in timpul analizei si pentru a evita erorile de acces la memorie sau interpretarea 
//incorecta a datelor
static uint32_t pe_rva_to_off(uint32_t rva,
                               PE_SectionHeader *secs, int nsecs) {
    for (int i=0; i<nsecs; i++) {
        uint32_t vs=secs[i].VirtualAddress;
        uint32_t ve=vs+secs[i].VirtualSize;
        if (rva>=vs && rva<ve)
            return secs[i].PointerToRawData+(rva-vs);
    }
    return 0;
}
#define PE_SCAN_SENCTION_NAME_SIZE 9
#define PE_SCAN_SECTION_NAME_LAST 8
#define PE_SECTION_CONST_ENTROPY 7.2

// Functie pentru a scana sectiunile din fisierul PE si a actualiza rezultatul scanarii in structura ScanResult,
// verificand caracteristicile sectiunilor, cum ar fi permisiunile de acces, prezenta sectiunilor cu entropie neobisnuit de mare 
// sau prezenta sectiunilor cu nume specifice care ar putea indica prezenta unui packer sau a unui criptor,
// si actualizand scorul de risc al fisierului in functie de aceste caracteristici pentru a oferi o evaluare a potentialului 
//comportament malitios al fisierului PE
static void pe_scan_sections(uint8_t *map, size_t fsz,
                              PE_SectionHeader *secs, int nsecs,
                              uint32_t ep_rva, ScanResult *r) {
    int ep_in_text = 0;

    for (int i=0; i<nsecs; i++) { // Iteram prin fiecare sectiune
        char name[PE_SCAN_SENCTION_NAME_SIZE]; memcpy(name, secs[i].Name, PE_SCAN_SECTION_NAME_LAST); name[PE_SCAN_SECTION_NAME_LAST]='\0';
        uint32_t flags = secs[i].Characteristics; 
        int exec  = (flags & PE_SCN_MEM_EXECUTE) != 0;
        int write = (flags & PE_SCN_MEM_WRITE)   != 0;

        if (exec && write) { r->wx_sections++; r->score += 3; }

        uint32_t vs=secs[i].VirtualAddress, ve=vs+secs[i].VirtualSize;
        // Verificam daca entry point-ul se afla in aceasta sectiune si 
        //daca numele sectiunii indica faptul ca ar putea fi sectiunea de cod principala (.text sau CODE)
        if (ep_rva>=vs && ep_rva<ve) {
            if (memcmp(name,".text",strlen(".text"))==0||memcmp(name,"CODE",4)==0)
                ep_in_text=1;
            else { r->ep_outside_text=1; r->score+=3; }
        }
        //Asemator pentru .ndata, .aspack sau UPX, care sunt sectiuni comune pentru fisierele protejate cu packere sau criptorii, 
        //si pentru a verifica daca sectiunea are o entropie neobisnuit de mare, ceea ce ar putea indica prezenta unui packer sau a unui criptor

        if (memcmp(name,"UPX",3)==0||memcmp(name,".ndata",strlen(".ndata"))==0||
            memcmp(name,".aspack",strlen(".aspack"))==0)
            { r->packer_sections++; r->score+=2; }

        if (secs[i].SizeOfRawData>0 &&
            secs[i].VirtualSize > secs[i].SizeOfRawData*4)
            { r->score+=2; }
        // Verificam daca sectiunea are o entropie neobisnuit de mare, ceea ce ar putea indica prezenta unui packer sau a unui criptor
        uint32_t off=secs[i].PointerToRawData, sz=secs[i].SizeOfRawData;
        if (off && sz && off+sz<=fsz) {
            double e = shannon(map+off, sz);
            if (e > PE_SECTION_CONST_ENTROPY) { r->high_entropy++; r->score+=2; }
        }
    }
    if (!ep_in_text) { r->ep_outside_text=1; r->score+=2; }
}
#define PE_SCAN_IMPORTS_CONST 0x80000000

// Functie pentru a scana importurile din fisierul PE si a actualiza rezultatul scanarii in structura ScanResult,
//verificand prezenta importurilor suspecte care ar putea indica faptul ca fisierul PE incearca sa utilizeze functii 
//care sunt adesea folosite in comportamente malitioase, cum ar fi injectia de cod sau tehnici anti-debugging, 
//si actualizand scorul de risc al fisierului in functie de aceste importuri pentru a oferi o evaluare a potentialului 
//comportament malitios al fisierului PE
static void pe_scan_imports(uint8_t *map, size_t fsz,
                             PE_SectionHeader *secs, int nsecs,
                             uint32_t import_rva, ScanResult *r) {
    if (!import_rva) { r->score+=2; return; }
    // Convertim adresa virtuala a importurilor (RVA) intr-un offset in fisier pentru a accesa corect datele despre importuri
    uint32_t off = pe_rva_to_off(import_rva, secs, nsecs);
    if (!off || off+sizeof(PE_ImportDescriptor)>fsz) { r->score+=1; return; }

    PE_ImportDescriptor *desc = (PE_ImportDescriptor*)(map+off);
    // Iteram prin fiecare descriptor de import si verificam functiile importate pentru a detecta prezenta unor importuri suspecte
    while (BOUNDS(desc, sizeof(PE_ImportDescriptor), map, fsz) && desc->Name) {
        uint32_t noff = pe_rva_to_off(desc->Name, secs, nsecs);
        if (!noff || noff>=fsz) break;

        uint32_t trva = desc->OriginalFirstThunk
                        ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t toff = pe_rva_to_off(trva, secs, nsecs);
        // Verificam fiecare functie importata pentru a vedea daca se afla in listele de simboluri suspecte si actualizam scorul de risc in consecinta
        if (toff && toff+sizeof(uint32_t)<=fsz) {
            uint32_t *thunk = (uint32_t*)(map+toff);
            while (BOUNDS(thunk, sizeof(uint32_t), map, fsz) && *thunk) {
                uint32_t t = *thunk;
                if (!(t & PE_SCAN_IMPORTS_CONST)) {
                    uint32_t hoff = pe_rva_to_off(t, secs, nsecs);
                    if (hoff+2 < fsz) {
                        const char *fn = (const char*)(map+hoff+2);
                        if      (in_list(fn, PE_INJECT))    r->inject_hits++;
                        else if (in_list(fn, PE_ANTIDEBUG)) r->antidebug_hits++;
                        else if (in_list(fn, PE_NETWORK))   r->network_hits++;
                    }
                }
                thunk++;
            }
        }
        desc++;
    }

    if (r->inject_hits >= 3) { r->inject_combo=1; r->score+=strlen("score"); } // 5
    else r->score += r->inject_hits * 2;
    r->score += r->antidebug_hits;
    if (r->network_hits) r->score += 1;
}
#define PE_SCAN_MAGIC_ADDR 0x20b
#define PE_SCAN_MACHINE_TYPE_X86 0x014c
#define PE_SCAN_MACHINE_TYPE_ARM64 0xaa64
#define PE_SCAN_MACHINE_TYPE_X86_64 0x8664
#define PE_MAP_112 112
#define PE_MAP_96 96
#define PE_MAP_8 8

// Functiile publice



// Functia aceasta scaneaza un fisier dat.
ScanResult pe_scanner_scan(const char *path) {
    // Initializam structura ScanResult cu valori implicite si deschidem fisierul pentru citire
    ScanResult r;
    memset(&r, 0, sizeof(r));
    r.verdict = SCAN_UNKNOWN_FORMAT;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return r;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return r; }
    size_t fsz = st.st_size;
    // Mapam fisierul in memorie pentru a putea accesa datele acestuia in timpul analizei
    uint8_t *map = mmap(NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return r;


    // Folosim madvise pentru a sugera sistemului de operare sa optimizeze accesul la fisier in mod secvential,
    // ceea ce poate imbunatati performanta scanarii
    #ifdef MADV_SEQUENTIAL
        madvise(map, fsz, MADV_SEQUENTIAL);
    #endif
    // Verificam daca fisierul incepe cu semnatura "MZ" si daca are un offset valid catre headerul PE, ceea ce indica faptul ca fisierul este in format PE
    if (fsz >= 2 && map[0]=='M' && map[1]=='Z') {
        r.is_pe = 1;
        DOS_Header *dos = (DOS_Header*)map;
        uint32_t pe_off = dos->e_lfanew;

        if (pe_off+4+sizeof(PE_FileHeader) > fsz ||
            memcmp(map+pe_off, "PE\0\0", 4) != 0) goto done;

        PE_FileHeader *fh = (PE_FileHeader*)(map+pe_off);
        PE_OptionalHeader_Common *oh =
            (PE_OptionalHeader_Common*)(map+pe_off+4+sizeof(PE_FileHeader));

        r.is_pe32plus  = (oh->Magic == PE_SCAN_MAGIC_ADDR);
        r.entry_point  = oh->AddressOfEntryPoint;
        r.num_sections = fh->NumberOfSections;

        switch(fh->Machine) {
            case PE_SCAN_MACHINE_TYPE_X86: r.machine="x86";    break;
            case PE_SCAN_MACHINE_TYPE_X86_64: r.machine="x86-64"; break;
            case PE_SCAN_MACHINE_TYPE_ARM64: r.machine="ARM64";  break;
            default:     r.machine="unknown";
        }

        uint32_t import_rva = 0;
        uint8_t *dd = map+pe_off+4+sizeof(PE_FileHeader)
                      +(r.is_pe32plus?PE_MAP_112:PE_MAP_96)+PE_MAP_8;
        if (BOUNDS(dd, 4, map, fsz)) import_rva = *(uint32_t*)dd;

        PE_SectionHeader *secs = (PE_SectionHeader*)
            (map+pe_off+4+sizeof(PE_FileHeader)+fh->SizeOfOptionalHeader);

        if (!BOUNDS(secs, r.num_sections*sizeof(PE_SectionHeader), map, fsz))
            goto done;

        pe_scan_sections(map, fsz, secs, r.num_sections,
                         (uint32_t)r.entry_point, &r);
        pe_scan_imports(map, fsz, secs, r.num_sections, import_rva, &r);

    }
done:
    munmap(map, fsz);

    if (r.is_pe) {
        if      (r.score >= PE_MAP_8) r.verdict = SCAN_HIGH_RISK;
        else if (r.score >= 4) r.verdict = SCAN_MODERATE_RISK;
        else                   r.verdict = SCAN_LOW_RISK;
    }

    return r;
}

// Functie pentru a extrage numele de baza al fisierului din calea completa
char* get_base_name(const char *path, char *buf) {
    const char *base = strrchr(path, '/');
    if (!base) base = path;
    else base++;
    (void)snprintf(buf, PE_256_BUFFER_SIZE, "%s", base);
    return buf;
}

// Pe scanner print (functia cu care printez rezultatele la final)
void pe_scanner_print(const char *path, int dst, const ScanResult *r) {
    char *path_buf = malloc(PE_256_BUFFER_SIZE);
    pe_write(dst, "=== Static Scanner ===\n", strlen("=== Static Scanner ===\n"));
    get_base_name(path, path_buf);
    pe_write(dst, "File:    ", strlen("File:    ")); pe_write(dst, path_buf, (int)strlen(path_buf)); pe_write(dst, "\n", strlen("\n"));
    free(path_buf);

    if (r->verdict == SCAN_UNKNOWN_FORMAT) {
        pe_write(dst, "Format:  UNKNOWN\n", strlen("Format:  UNKNOWN\n"));
        return;
    }

    pe_write(dst, "Format:  ", strlen("Format:  "));
    if (r->is_pe)
        pe_write(dst, r->is_pe32plus ? "PE32+\n" : "PE32\n", (int)strlen(r->is_pe32plus ? "PE32+\n" : "PE32\n"));

    pe_write(dst, "Machine: ", strlen("Machine: ")); pe_write(dst, r->machine ? r->machine : "unknown", (int)strlen(r->machine ? r->machine : "unknown"));   pe_write(dst, "\n", strlen("\n"));
    pe_write(dst, "Entry:   ", strlen("Entry:   ")); s_hex(r->entry_point, dst); pe_write(dst, "\n", strlen("\n"));

    if (r->inject_combo)    pe_write(dst, "[!!] process injection combo\n", strlen("[!!] process injection combo\n"));
    if (r->inject_hits)   { pe_write(dst, "[!!] inject imports: ", strlen("[!!] inject imports: ")); s_uint(r->inject_hits, dst); pe_write(dst, "\n", strlen("\n")); }
    if (r->antidebug_hits){ pe_write(dst, "[!]  anti-debug hits: ", strlen("[!]  anti-debug hits: ")); s_uint(r->antidebug_hits, dst); pe_write(dst, "\n", strlen("\n")); }
    if (r->network_hits)  { pe_write(dst, "[~]  network imports: ", strlen("[~]  network imports: ")); s_uint(r->network_hits, dst); pe_write(dst, "\n", strlen("\n")); }
    if (r->wx_sections)   { pe_write(dst, "[!]  WX sections: ", strlen("[!]  WX sections: ")); s_uint(r->wx_sections, dst); pe_write(dst, "\n", strlen("\n")); }
    if (r->ep_outside_text) pe_write(dst, "[!]  entry point outside .text\n", strlen("[!]  entry point outside .text\n"));
    if (r->packer_sections) pe_write(dst, "[!]  packer section names detected\n", strlen("[!]  packer section names detected\n"));
    if (r->high_entropy)  { pe_write(dst, "[!]  high entropy sections: ", strlen("[!]  high entropy sections: ")); s_uint(r->high_entropy, dst); pe_write(dst, "\n", strlen("\n")); }

    pe_write(dst, "Score:   ", strlen("Score:   ")); s_uint(r->score, dst); pe_write(dst, "\n", strlen("\n"));
    pe_write(dst, "Verdict: ", strlen("Verdict: ")); pe_write(dst, pe_scanner_verdict_str(r->verdict), (int)strlen(pe_scanner_verdict_str(r->verdict))); pe_write(dst, "\n", strlen("\n"));
}


// Functia pentru a converti verdictul scanarii intr-un sir de caractere pentru a putea afisa verdictul ca string
const char *pe_scanner_verdict_str(ScanVerdict v) {
    switch(v) {
        case SCAN_HIGH_RISK:      return "HIGH RISK";
        case SCAN_MODERATE_RISK:  return "MODERATE RISK";
        case SCAN_LOW_RISK:       return "LOW RISK";
        default:                  return "UNKNOWN";
    }
}

// Functie wrapper pentru a scana un fisier direct (face automat si initializarea)
ScanVerdict pe_scan_file(const char *path) {
    ScanResult r = pe_scanner_scan(path);
    memset(&r, 0, sizeof(r));
    r.verdict = SCAN_UNKNOWN_FORMAT;
    r.machine = "unknown"; 
    return r.verdict;
}


